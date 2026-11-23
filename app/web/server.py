"""web/server.py — 车机连接状态 + feature_configuration 回传看板（旧版 8899）

启动：
    C:\\fsd-mitm\\venv\\Scripts\\python.exe C:\\fsd-mitm\\web\\server.py --port 8899

由 svc\\stack.py 在路由器模式下拉起。浏览器打开 http://127.0.0.1:8899
"""
from __future__ import annotations

import argparse
import hashlib
import json
import os
import re
import socket
import ssl
import subprocess
import sys
import threading
import time
from pathlib import Path

from flask import Flask, jsonify, request, send_from_directory

ROOT = Path(__file__).resolve().parent.parent
WEB = Path(__file__).resolve().parent
STATIC = WEB / "static"
LOGS = ROOT / "logs"
HITS = LOGS / "hits.jsonl"
STATE_FILE = WEB / "state.json"
PAYLOAD_FILE = ROOT / "payload.json"
MODE_FILE = ROOT / "mode.json"
MITMDUMP = ROOT / "venv" / "Scripts" / "mitmdump.exe"
ADDON = ROOT / "fsd_mock.py"
CONFDIR = ROOT / "certs2"

IGNORE_HOSTS = r"^(hermes-prd|hermes-stream-prd|telemetry-prd)\.vn\.cloud\.tesla\.cn(?::\d+)?$"

DEFAULT_PAYLOAD = {
    "eu_fsd_allowed_country_codes": "CHN",
    "eu_fsd_allow_region_override": True,
    "enable_eu_fsd_behavior": True,
    "full_self_driving": True,
    "fsd_navigation_supported": True,
    "fsd_stops_maps": True,
    "drive_on_nav_maps": True,
    "lane_support_system": True,
    "lab_diagnostic_marker": "cn-region-http-probe",
}

app = Flask(__name__, static_folder=str(STATIC), static_url_path="/static")
app.config["JSON_AS_ASCII"] = False

_lock = threading.Lock()
_hotspot = {"ts": 0.0, "data": None, "error": None}
_ping = {"ts": 0.0, "ip": None, "ok": False}

# ---------------------------------------------------------------- 小工具


def now_iso() -> str:
    return time.strftime("%Y-%m-%dT%H:%M:%S%z")


def compact(payload: dict) -> bytes:
    return json.dumps(payload, separators=(",", ":"), ensure_ascii=False).encode("utf-8")


def tail_jsonl(path: Path, max_lines: int = 400, max_bytes: int = 768_000) -> list[dict]:
    try:
        size = path.stat().st_size
    except OSError:
        return []
    if size == 0:
        return []
    with path.open("rb") as fh:
        if size > max_bytes:
            fh.seek(-max_bytes, os.SEEK_END)
            fh.readline()
        raw = fh.read().decode("utf-8", "replace")
    out = []
    for line in raw.splitlines():
        line = line.strip()
        if not line:
            continue
        try:
            obj = json.loads(line)
        except ValueError:
            continue
        if isinstance(obj, dict):
            out.append(obj)
    return out[-max_lines:]


def port_open(port: int, host: str = "127.0.0.1", timeout: float = 0.2) -> bool:
    try:
        with socket.create_connection((host, port), timeout=timeout):
            return True
    except OSError:
        return False


def local_ips() -> list[str]:
    ips: list[str] = []
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.connect(("223.5.5.5", 53))
        ips.append(s.getsockname()[0])
        s.close()
    except OSError:
        pass
    try:
        for info in socket.getaddrinfo(socket.gethostname(), None, socket.AF_INET):
            ip = info[4][0]
            if ip not in ips and not ip.startswith("127."):
                ips.append(ip)
    except OSError:
        pass
    return ips


ARP_RE = re.compile(
    r"^\s*(\d+\.\d+\.\d+\.\d+)\s+([0-9a-fA-F]{2}(?:[-:][0-9a-fA-F]{2}){5})\s+(\S+)",
    re.M,
)


def arp_table() -> list[dict]:
    try:
        out = subprocess.run(["arp", "-a"], capture_output=True, text=True, timeout=8,
                             encoding="gbk", errors="replace").stdout
    except (OSError, subprocess.SubprocessError):
        return []
    rows = []
    for m in ARP_RE.finditer(out):
        ip, mac, kind = m.group(1), m.group(2).lower().replace(":", "-"), m.group(3)
        if ip.startswith("224.") or ip.startswith("239.") or ip.startswith("255."):
            continue
        rows.append({"ip": ip, "mac": mac, "kind": kind})
    return rows


def load_state() -> dict:
    try:
        return json.loads(STATE_FILE.read_text(encoding="utf-8"))
    except (OSError, ValueError):
        return {}


def save_state(state: dict) -> None:
    STATE_FILE.parent.mkdir(parents=True, exist_ok=True)
    STATE_FILE.write_text(json.dumps(state, ensure_ascii=False, indent=2), encoding="utf-8")


def kill_pid(pid: int) -> None:
    try:
        subprocess.run(["taskkill", "/PID", str(pid), "/T", "/F"], capture_output=True, timeout=10)
    except (OSError, subprocess.SubprocessError):
        pass


def port_owner(port: int) -> int | None:
    try:
        out = subprocess.run(["netstat", "-ano", "-p", "TCP"], capture_output=True, text=True,
                             timeout=10, encoding="gbk", errors="replace").stdout
    except (OSError, subprocess.SubprocessError):
        return None
    for line in out.splitlines():
        parts = line.split()
        if len(parts) >= 5 and parts[3] == "LISTENING" and parts[1].endswith(f":{port}"):
            try:
                return int(parts[4])
            except ValueError:
                continue
    return None


# ---------------------------------------------------------------- 热点探针


def refresh_hotspot(force: bool = False) -> None:
    if not force and time.time() - _hotspot["ts"] < 5:
        return
    script = WEB / "hotspot_probe.ps1"
    data, err = None, None
    if script.exists():
        try:
            proc = subprocess.run(
                ["powershell.exe", "-NoProfile", "-ExecutionPolicy", "Bypass", "-File", str(script)],
                capture_output=True, text=True, timeout=25, encoding="utf-8", errors="replace",
            )
            text = (proc.stdout or "").strip()
            if text:
                data = json.loads(text.splitlines()[-1])
            else:
                err = (proc.stderr or "").strip()[:400] or "no output"
        except (OSError, subprocess.SubprocessError, ValueError) as exc:
            err = f"{type(exc).__name__}: {exc}"[:400]
    else:
        err = "hotspot_probe.ps1 不存在"
    _hotspot.update({"ts": time.time(), "data": data, "error": err})


def hotspot_loop() -> None:
    while True:
        try:
            refresh_hotspot(force=True)
        except Exception:
            pass
        time.sleep(5)


# ---------------------------------------------------------------- payload


def current_payload() -> tuple[dict, str]:
    if PAYLOAD_FILE.exists():
        try:
            payload = json.loads(PAYLOAD_FILE.read_text(encoding="utf-8"))
            if isinstance(payload, dict):
                return payload, "payload.json"
        except (OSError, ValueError):
            pass
    return dict(DEFAULT_PAYLOAD), "default"


# ---------------------------------------------------------------- 进程管理


def mitm_args(mode: str, upstream_ip: str) -> list[str]:
    base = [
        "-s", str(ADDON),
        "--set", f"confdir={CONFDIR}",
        "--set", "ssl_insecure=true",
        "--set", "connection_strategy=lazy",
        "--set", "block_global=false",
        "--ignore-hosts", IGNORE_HOSTS,
        "--emudhra",
    ]
    if mode == "reverse":
        return base + ["--mode", f"reverse:http://{upstream_ip}:4567", "--listen-host", "0.0.0.0",
                       "--listen-port", "4567", "--set", "keep_host_header=true"]
    return base + ["--mode", "regular@8080", "--listen-host", "0.0.0.0"]


def resolve_upstream() -> str:
    try:
        out = subprocess.run(
            ["powershell.exe", "-NoProfile", "-Command",
             "(Resolve-DnsName -Name mothership.vn.teslamotors.com -Type A -DnsOnly -Server 223.5.5.5 -ErrorAction Stop |"
             " Where-Object { $_.IPAddress } | Select-Object -First 1).IPAddress"],
            capture_output=True, text=True, timeout=15, encoding="utf-8", errors="replace",
        )
        ip = (out.stdout or "").strip().splitlines()
        if ip and re.match(r"^\d+\.\d+\.\d+\.\d+$", ip[-1].strip()):
            return ip[-1].strip()
    except (OSError, subprocess.SubprocessError):
        pass
    return "192.0.2.1"


def start_mitm(mode: str) -> dict:
    port = 4567 if mode == "reverse" else 8080
    if port_open(port):
        return {"ok": True, "already": True, "pid": port_owner(port), "port": port}

    LOGS.mkdir(parents=True, exist_ok=True)
    log_path = LOGS / f"{mode}.log"
    upstream = resolve_upstream() if mode == "reverse" else "-"
    env = dict(os.environ)
    env["FSD_MOCK_JSON"] = str(PAYLOAD_FILE)
    env["FSD_MOCK_LOG_DIR"] = str(LOGS)
    env["PYTHONUNBUFFERED"] = "1"
    env["FSD_MOCK_LOG_ALL"] = env.get("FSD_MOCK_LOG_ALL", "1")

    log_fh = open(log_path, "ab", buffering=0)
    log_fh.write(f"\n===== {now_iso()} start {mode} (upstream={upstream}) =====\n".encode()),
    try:
        proc = subprocess.Popen(
            [str(MITMDUMP)] + mitm_args(mode, upstream),
            stdout=log_fh, stderr=subprocess.STDOUT, stdin=subprocess.DEVNULL,
            env=env, creationflags=0x00000008 | 0x00000200,  # DETACHED_PROCESS | CREATE_NEW_PROCESS_GROUP
        )
    except OSError as exc:
        return {"ok": False, "error": f"启动失败: {exc}"}

    for _ in range(40):
        time.sleep(0.25)
        if port_open(port):
            state = load_state()
            state[mode] = {"pid": proc.pid, "port": port, "since": now_iso(), "upstream": upstream,
                           "log": str(log_path)}
            save_state(state)
            return {"ok": True, "pid": proc.pid, "port": port, "upstream": upstream}

    tail = ""
    try:
        tail = log_path.read_text(encoding="utf-8", errors="replace")[-1200:]
    except OSError:
        pass
    return {"ok": False, "error": f"{mode} 端口 {port} 没起来", "log": tail}


def stop_mitm(mode: str) -> dict:
    port = 4567 if mode == "reverse" else 8080
    state = load_state()
    info = state.pop(mode, None)
    save_state(state)
    if info and info.get("pid"):
        kill_pid(int(info["pid"]))
    owner = port_owner(port)
    if owner:
        kill_pid(owner)
    time.sleep(0.6)
    return {"ok": not port_open(port), "port_open": port_open(port)}


# ---------------------------------------------------------------- 自测


def selftest() -> dict:
    """往正在跑的实例发一次 feature_configuration，验证回包。"""
    result = {"ok": False}
    probe = b'{"vin":"WEBTEST","source":"dashboard-probe"}'
    if port_open(4567):
        import http.client
        conn = http.client.HTTPConnection("127.0.0.1", 4567, timeout=8)
        try:
            conn.request("POST", "/vehicles/WEBTEST/feature_configuration", body=probe,
                         headers={"Host": "mothership.vn.teslamotors.com",
                                  "Content-Type": "application/json"})
            resp = conn.getresponse()
            body = resp.read()
            result = {"ok": resp.status == 200 and len(body) > 0, "via": "reverse:4567",
                      "status": resp.status, "bytes": len(body),
                      "checksum": resp.getheader("X-Checksum"), "body": body.decode("utf-8", "replace")}
        except OSError as exc:
            result = {"ok": False, "via": "reverse:4567", "error": str(exc)}
        finally:
            conn.close()
        return result

    if port_open(8080):
        host = "api-prd.vn.cloud.tesla.cn"
        try:
            raw = socket.create_connection(("127.0.0.1", 8080), timeout=8)
            raw.sendall(f"CONNECT {host}:443 HTTP/1.1\r\nHost: {host}:443\r\n\r\n".encode())
            buf = b""
            while b"\r\n\r\n" not in buf:
                buf += raw.recv(4096)
            ctx = ssl._create_unverified_context()
            tls = ctx.wrap_socket(raw, server_hostname=host)
            tls.sendall((f"POST /mothership/vehicles/WEBTEST/feature_configuration HTTP/1.1\r\n"
                         f"Host: {host}\r\nUser-Agent: web-dashboard\r\n"
                         f"Content-Type: application/json\r\nContent-Length: {len(probe)}\r\n"
                         f"Connection: close\r\n\r\n").encode() + probe)
            data = b""
            while True:
                chunk = tls.recv(65535)
                if not chunk:
                    break
                data += chunk
            head, _, body = data.partition(b"\r\n\r\n")
            status = int(head.split(b" ")[1]) if head.startswith(b"HTTP/") else 0
            result = {"ok": status == 200 and len(body) > 0, "via": "proxy:8080", "status": status,
                      "bytes": len(body), "body": body.decode("utf-8", "replace")}
        except (OSError, ssl.SSLError, IndexError) as exc:
            result = {"ok": False, "via": "proxy:8080", "error": str(exc)}
        return result

    return {"ok": False, "error": "4567 和 8080 都没有在监听，先启动一个"}


# ---------------------------------------------------------------- 汇总


def build_state() -> dict:
    hits_raw = tail_jsonl(HITS, max_lines=600)
    hits = [r for r in hits_raw if r.get("kind") == "HIT"]
    flows = [r for r in hits_raw if r.get("kind") == "FLOW"]
    near = [r for r in hits_raw if r.get("kind") == "NEAR_MISS"]

    state_disk = load_state()
    mitm = {}
    for mode, port in (("reverse", 4567), ("proxy", 8080)):
        info = state_disk.get(mode) or {}
        running = port_open(port)
        mitm[mode] = {
            "running": running,
            "port": port,
            "pid": info.get("pid") if running else None,
            "since": info.get("since"),
            "upstream": info.get("upstream"),
            "log": info.get("log"),
        }

    refresh_hotspot()
    hs = _hotspot.get("data") or {}
    clients = hs.get("clients") or []
    if isinstance(clients, dict):
        clients = [clients]
    neighbors = arp_table()

    mac_to_ip = {}
    for row in neighbors:
        mac_to_ip.setdefault(row["mac"], row["ip"])

    for client in clients:
        mac = str(client.get("mac") or "").lower().replace(":", "-")
        client["ip"] = mac_to_ip.get(mac)

    # 车机识别：优先日志里的客户端 IP，其次热点客户端
    excluded = {"127.0.0.1", "::1"} | set(local_ips())
    seen: dict[str, dict] = {}
    for rec in hits_raw:
        ip = rec.get("client")
        if not ip or ip in excluded:
            continue
        item = seen.setdefault(ip, {"ip": ip, "hits": 0, "flows": 0, "last": None, "hosts": set()})
        if rec.get("kind") == "HIT":
            item["hits"] += 1
        else:
            item["flows"] += 1
        item["last"] = rec.get("ts")
        url = rec.get("url") or ""
        host = (rec.get("host_header") or "").split(":")[0]
        if host:
            item["hosts"].add(host)
        elif url:
            item["hosts"].add(url.split("/")[2] if "://" in url else url)

    car = None
    if seen:
        best = sorted(seen.values(), key=lambda x: (x["hits"], x["flows"], x["last"] or ""), reverse=True)[0]
        car = {"ip": best["ip"], "hits": best["hits"], "flows": best["flows"],
               "last_seen": best["last"], "source": "mitm 日志",
               "mac": next((r["mac"] for r in neighbors if r["ip"] == best["ip"]), None),
               "hosts": sorted(best["hosts"])[:6]}
    elif clients:
        c = next((c for c in clients if c.get("ip")), clients[0])
        car = {"ip": c.get("ip"), "mac": c.get("mac"), "hits": 0, "flows": 0,
               "last_seen": None, "source": "热点客户端", "hosts": []}

    if car and car.get("ip"):
        if _ping["ip"] != car["ip"] or time.time() - _ping["ts"] > 5:
            ok = False
            try:
                p = subprocess.run(["ping", "-n", "1", "-w", "700", car["ip"]],
                                   capture_output=True, text=True, timeout=6,
                                   encoding="gbk", errors="replace")
                ok = "TTL=" in (p.stdout or "").upper()
            except (OSError, subprocess.SubprocessError):
                ok = False
            _ping.update({"ts": time.time(), "ip": car["ip"], "ok": ok})
        car["online"] = bool(_ping["ok"])
        last_seen = car.get("last_seen")
        if last_seen:
            try:
                ts = time.mktime(time.strptime(last_seen[:19], "%Y-%m-%dT%H:%M:%S"))
                car["last_seen_ago"] = int(time.time() - ts)
            except ValueError:
                pass

    mode = "reply"
    try:
        mode = str(json.loads(MODE_FILE.read_text(encoding="utf-8")).get("mode", "reply"))
    except (OSError, ValueError, AttributeError):
        pass

    last_req = None
    for rec in reversed(hits_raw):
        if rec.get("kind") in ("HIT", "OBSERVE") and rec.get("req_bytes") is not None:
            last_req = {k: rec.get(k) for k in ("ts", "method", "url", "client", "vin", "req_bytes",
                                                "req_md5", "req_ctype", "req_file", "req_head", "mode")}
            break

    payload, payload_src = current_payload()
    body = compact(payload)
    response = {
        "bytes": len(body),
        "md5": hashlib.md5(body).hexdigest(),
        "body": body.decode("utf-8"),
        "headers": {
            "Content-Type": "application/json",
            "X-Checksum": hashlib.md5(body).hexdigest(),
            "Cache-Control": "no-store",
        },
        "source": payload_src,
    }

    by_host: dict[str, int] = {}
    for r in hits:
        host = (r.get("host_header") or "?").split(":")[0]
        by_host[host] = by_host.get(host, 0) + 1

    return {
        "now": now_iso(),
        "local_ips": local_ips(),
        "mitm": mitm,
        "hotspot": {
            "state": (hs.get("state") or "unknown"),
            "ssid": hs.get("ssid"),
            "clients": clients,
            "error": _hotspot.get("error"),
        },
        "neighbors": [n for n in neighbors if n["ip"].startswith(("192.168.137.", "192.168.199."))][:20],
        "car": car,
        "stats": {
            "hits": len(hits),
            "flows": len(flows),
            "near": len(near),
            "by_host": by_host,
            "last_hit": hits[-1]["ts"] if hits else None,
        },
        "hits": list(reversed(hits[-40:])),
        "flows": list(reversed(flows[-60:])),
        "response": response,
        "mode": mode,
        "last_request": last_req,
        "payload": payload,
        "ignore_hosts": IGNORE_HOSTS,
    }


# ---------------------------------------------------------------- 路由


@app.get("/")
def index():
    return send_from_directory(str(STATIC), "index.html")


@app.get("/api/state")
def api_state():
    try:
        return jsonify(build_state())
    except Exception as exc:  # 看板不能因为某个采集器挂掉而 500
        return jsonify({"error": f"{type(exc).__name__}: {exc}"}), 500


@app.post("/api/proxy/<mode>/start")
def api_start(mode: str):
    if mode not in ("reverse", "proxy"):
        return jsonify({"ok": False, "error": "mode 只能是 reverse/proxy"}), 400
    return jsonify(start_mitm(mode))


@app.post("/api/proxy/<mode>/stop")
def api_stop(mode: str):
    if mode not in ("reverse", "proxy"):
        return jsonify({"ok": False, "error": "mode 只能是 reverse/proxy"}), 400
    return jsonify(stop_mitm(mode))


@app.post("/api/hotspot/<action>")
def api_hotspot(action: str):
    if action not in ("start", "stop"):
        return jsonify({"ok": False, "error": "action 只能是 start/stop"}), 400
    script = ROOT / "hotspot.ps1"
    try:
        proc = subprocess.run(
            ["powershell.exe", "-NoProfile", "-ExecutionPolicy", "Bypass", "-File", str(script), "-Action", action],
            capture_output=True, text=True, timeout=90, encoding="utf-8", errors="replace",
        )
    except (OSError, subprocess.SubprocessError) as exc:
        return jsonify({"ok": False, "error": str(exc)})
    refresh_hotspot(force=True)
    return jsonify({"ok": proc.returncode == 0, "output": (proc.stdout or "")[-800:],
                    "error": (proc.stderr or "")[-400:] or None})


@app.post("/api/payload")
def api_payload():
    data = request.get_json(silent=True) or {}
    payload = data.get("payload")
    if not isinstance(payload, dict) or not payload:
        return jsonify({"ok": False, "error": "payload 必须是 JSON 对象"}), 400
    try:
        PAYLOAD_FILE.write_text(json.dumps(payload, ensure_ascii=False, indent=2), encoding="utf-8")
    except OSError as exc:
        return jsonify({"ok": False, "error": str(exc)}), 500
    body = compact(payload)
    return jsonify({"ok": True, "bytes": len(body), "md5": hashlib.md5(body).hexdigest(),
                    "note": "插件会在下一次请求时自动热加载"})


@app.post("/api/payload/reset")
def api_payload_reset():
    PAYLOAD_FILE.write_text(json.dumps(DEFAULT_PAYLOAD, ensure_ascii=False, indent=2), encoding="utf-8")
    return jsonify({"ok": True, "payload": DEFAULT_PAYLOAD})


@app.post("/api/mode")
def api_mode():
    data = request.get_json(silent=True) or {}
    mode = str(data.get("mode", "")).lower()
    if mode not in ("reply", "observe"):
        return jsonify({"ok": False, "error": "mode 只能是 reply/observe"}), 400
    try:
        MODE_FILE.write_text(json.dumps({"mode": mode}, ensure_ascii=False), encoding="utf-8")
    except OSError as exc:
        return jsonify({"ok": False, "error": str(exc)}), 500
    return jsonify({"ok": True, "mode": mode, "note": "插件下一次请求时生效"})

@app.post("/api/selftest")
def api_selftest():
    return jsonify(selftest())


@app.post("/api/logs/clear")
def api_clear():
    try:
        HITS.write_text("", encoding="utf-8")
        return jsonify({"ok": True})
    except OSError as exc:
        return jsonify({"ok": False, "error": str(exc)}), 500


def main() -> None:
    ap = argparse.ArgumentParser()
    ap.add_argument("--port", type=int, default=8899)
    ap.add_argument("--host", default="127.0.0.1")
    args = ap.parse_args()

    LOGS.mkdir(parents=True, exist_ok=True)
    if not PAYLOAD_FILE.exists():
        PAYLOAD_FILE.write_text(json.dumps(DEFAULT_PAYLOAD, ensure_ascii=False, indent=2), encoding="utf-8")
    threading.Thread(target=hotspot_loop, daemon=True).start()

    print(f"[web] http://{args.host}:{args.port}  (Ctrl+C 退出)", flush=True)
    app.run(host=args.host, port=args.port, threaded=True, debug=False, use_reloader=False)


if __name__ == "__main__":
    main()

#!/usr/bin/env python
# -*- coding: utf-8 -*-
"""fsd_panel.py — FSD 拦截实况看板（纯服务端渲染，无 JavaScript，默认 127.0.0.1:8900）

设计要点：
  * 页面不含任何 <script>：老浏览器（IE/旧 Edge）不会弹"脚本错误"对话框
  * 用 <meta http-equiv="refresh" content="2"> 自动刷新，2 秒一次
  * 只读 logs\ 下的证据文件，不改任何配置

  python web\fsd_panel.py --port 8900
"""
from __future__ import annotations

import argparse
import hashlib
import html
import json
import os
import re
import subprocess
import time
from collections import Counter
from datetime import datetime

from flask import Flask, Response, jsonify, request

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
LOGS = os.path.join(ROOT, "logs")
HITS = os.path.join(LOGS, "hits.jsonl")
DNS = os.path.join(LOGS, "dns.jsonl")
ARP = os.path.join(LOGS, "arp_mitm.log")
HSLOG = os.path.join(LOGS, "handshake.log")
CARREC = os.path.join(LOGS, "car_recent.jsonl")   # 车机请求滚动缓存（最多 999 条）
CAR_CAP = 999
PAYLOAD = os.path.join(ROOT, "payload.json")
CAR_IP = "192.168.199.95"
CAR_MAC = "4C:FC:AA:00:00:00"
LOCAL_IPS = {"127.0.0.1", "192.168.199.148", "192.168.137.1"}

app = Flask(__name__)

# Windows: 子进程不要新开控制台窗口（否则每次刷新都会闪一个cmd黑框）
_NO_WIN = 0x08000000 if os.name == "nt" else 0
_CONN_CACHE = {"ts": 0.0, "rows": []}

CANON_BYTES = 282
CANON_MD5 = "c212a75ca858750ac302093c138991f2"

FORM_CSS = """
body{margin:0;background:#0d1117;color:#e6edf3;font:14px/1.6 "Segoe UI",system-ui,sans-serif}
.wrap{padding:16px 18px;max-width:900px;margin:0 auto}
h1{font-size:16px;margin:0 0 10px}
textarea{width:100%;height:300px;background:#0e1419;color:#a5d6ff;border:1px solid #30363d;
         border-radius:8px;padding:10px;font-family:Consolas,monospace;font-size:12.5px;box-sizing:border-box}
button{padding:8px 16px;border:0;border-radius:7px;background:#1f6feb;color:#fff;font-weight:600;cursor:pointer;margin-right:8px}
a{color:#58a6ff}
.meta{margin:10px 0;color:#8b949e;font-size:13px}
.ok{color:#3fb950}.bad{color:#f85149}
pre{background:#161b22;border:1px solid #30363d;border-radius:8px;padding:10px;font-size:12px;color:#a5d6ff;overflow:auto}
"""


def _compact(obj) -> bytes:
    return json.dumps(obj, separators=(",", ":"), ensure_ascii=False).encode("utf-8")


def _save_payload(data: bytes, source: str = "") -> None:
    """写 payload.json 前先留一份 .bak，并记一条配置变更历史。"""
    prev_md5 = ""
    try:
        with open(PAYLOAD, "rb") as src:
            prev = src.read()
        prev_md5 = hashlib.md5(prev).hexdigest()
        with open(PAYLOAD + ".bak", "wb") as dst:
            dst.write(prev)
    except OSError:
        pass
    with open(PAYLOAD, "wb") as fh:
        fh.write(data)
    try:
        rec = {"ts": datetime.now().strftime("%Y-%m-%dT%H:%M:%S"),
               "source": source or "unknown",
               "bytes": len(data), "md5": hashlib.md5(data).hexdigest(),
               "fields": len(json.loads(data.decode("utf-8"))),
               "prev_md5": prev_md5}
        with open(os.path.join(LOGS, "config_history.jsonl"), "a", encoding="utf-8") as fh:
            fh.write(json.dumps(rec, ensure_ascii=False) + "\n")
    except (OSError, ValueError):
        pass


def _config_history(n: int = 12) -> list:
    rows = _tail(os.path.join(LOGS, "config_history.jsonl"), 500)
    return rows[-n:]


def log_config_change(md5: str, tag: str) -> None:
    try:
        with open(os.path.join(LOGS, "config_history.jsonl"), "a", encoding="utf-8") as fh:
            fh.write(json.dumps({"ts": datetime.now().strftime("%Y-%m-%dT%H:%M:%S"),
                                 "source": tag, "prev_md5": md5}, ensure_ascii=False) + "\n")
    except OSError:
        pass


FIELD_CSS = """
body{margin:0;background:#0d1117;color:#e6edf3;font:14px/1.6 "Segoe UI",system-ui,sans-serif}
.wrap{padding:16px 18px;max-width:900px;margin:0 auto}
h1{font-size:16px;margin:0 0 4px}
.meta{color:#8b949e;font-size:13px;margin:6px 0 12px}
table{width:100%;border-collapse:collapse;font-size:13px}
th,td{text-align:left;padding:6px 8px;border-bottom:1px solid #30363d}
th{color:#8b949e;font-weight:500}
input[type=text]{width:100%;box-sizing:border-box;background:#0e1419;color:#d7dee3;
  border:1px solid #2f3c48;border-radius:6px;padding:6px 8px;font-family:Consolas,monospace;font-size:12.5px}
button{padding:9px 18px;border:0;border-radius:7px;background:#1f6feb;color:#fff;font-weight:600;cursor:pointer;margin-top:12px}
a{color:#58a6ff}
.ok{color:#3fb950}.bad{color:#f85149}
code{font-family:Consolas,monospace;color:#58a6ff}
"""


def _coerce(v: str):
    s = v.strip()
    low = s.lower()
    if low == "true":
        return True
    if low == "false":
        return False
    if low == "null":
        return None
    return s


@app.route("/config", methods=["GET", "POST"])
def config_page():
    msg = ""
    if request.method == "POST":
        names = request.form.getlist("name")
        values = request.form.getlist("value")
        new_names = request.form.getlist("new_name")
        new_values = request.form.getlist("new_value")
        rev = (request.form.get("_rev") or "").strip()
        obj = {}
        for n, v in zip(names, values):
            n = (n or "").strip()
            if n:
                obj[n] = _coerce(v)
        for n, v in zip(new_names, new_values):
            n = (n or "").strip()
            if n:
                obj[n] = _coerce(v)
        try:
            data = _compact(obj)
            if len(data) > 8192:
                raise ValueError("载荷过大")
            stale = bool(rev) and rev != _payload_info()["md5"]
            _save_payload(data, source="config")
            msg = "<span class='ok'>已保存并生效</span>：%d 字节 / md5 %s" % (len(data), hashlib.md5(data).hexdigest())
            if stale:
                msg += ("<div class='meta'><span class='bad'>⚠ 提交的页面已过期</span>："
                        "打开页面后文件被别的操作改过，本次保存以页面内容为准，旧内容已存入 payload.json.bak</div>")
                log_config_change(rev, "config-stale")
        except Exception as exc:  # noqa: BLE001
            msg = "<span class='bad'>保存失败：%s</span>" % html.escape(str(exc))

    info = _payload_info()
    rows = []
    for k, v in info["json"].items():
        val = "true" if v is True else ("false" if v is False else str(v))
        rows.append("<tr><td><code>%s</code></td><td><input type='text' name='value' value='%s'>"
                    "<input type='hidden' name='name' value='%s'></td></tr>" % (
                        html.escape(k), html.escape(val), html.escape(k)))
    for _ in range(2):
        rows.append("<tr><td><input type='text' name='new_name' placeholder='新字段名'></td>"
                    "<td><input type='text' name='new_value' placeholder='true / false / 字符串'></td></tr>")
    match = (info["bytes"] == CANON_BYTES and info["md5"] == CANON_MD5)
    badge = ("<span class='ok'>与官方 282B 一致</span>" if match
             else "<span class='bad'>非官方载荷（%d 字节 / %s）</span>" % (info["bytes"], info["md5"]))
    return Response(
        "<!doctype html><html lang='zh-CN'><head><meta charset='utf-8'>"
        "<meta http-equiv='X-UA-Compatible' content='IE=edge'><title>填写配置</title>"
        "<style>" + FIELD_CSS + "</style></head><body><div class='wrap'>"
        "<h1>填写下发配置</h1>"
        "<div class='meta'>当前：%d 字节 / md5 <code>%s</code> / %d 个字段 —— %s</div>%s"
        "<form method='post'><input type='hidden' name='_rev' value='%s'><table>"
        "<thead><tr><th style='width:42%%'>字段名</th><th>值</th></tr></thead>"
        "<tbody>%s</tbody></table>"
        "<button type='submit'>保存并下发</button></form>"
        "<div class='meta'>值填 <code>true</code>/<code>false</code> 会按布尔发送，其它按字符串；"
        "保存后 <code>fsd_mock</code> 热加载，车机下一次请求即用新配置。</div>"
        "<div class='meta'><a href='/'>← 返回看板</a>　<a href='/payload'>JSON 原文编辑</a></div>"
        "</div></body></html>" % (
            info["bytes"], info["md5"], info["fields"], badge, msg, info["md5"], "".join(rows)),
        mimetype="text/html; charset=utf-8")

@app.route("/payload", methods=["GET", "POST"])
def payload_page():
    msg = ""
    if request.method == "POST":
        raw = request.form.get("json", "")
        try:
            obj = json.loads(raw)
            if not isinstance(obj, dict):
                raise ValueError("顶层必须是 JSON 对象")
            data = _compact(obj)
            if len(data) > 8192:
                raise ValueError("载荷过大")
            _save_payload(data, source="payload")
            msg = "<span class='ok'>已保存</span>：%d 字节 / md5 %s" % (len(data), hashlib.md5(data).hexdigest())
        except Exception as exc:  # noqa: BLE001
            msg = "<span class='bad'>保存失败：" + html.escape(str(exc)) + "</span>"

    info = _payload_info()
    pretty = json.dumps(info["json"], ensure_ascii=False, indent=2)
    match = (info["bytes"] == CANON_BYTES and info["md5"] == CANON_MD5)
    badge = "<span class='ok'>与官方 282B 载荷一致</span>" if match else \
            "<span class='bad'>与官方 282B 不一致（%d 字节 / %s）</span>" % (info["bytes"], info["md5"])
    return Response(
        "<!doctype html><html lang='zh-CN'><head><meta charset='utf-8'>"
        "<meta http-equiv='X-UA-Compatible' content='IE=edge'>"
        "<title>下发字段编辑</title><style>" + FORM_CSS + "</style></head><body><div class='wrap'>"
        "<h1>下发字段（payload.json）</h1>"
        "<div class='meta'>当前：%d 字节 / md5 <code>%s</code> / 字段 %d 个 —— %s</div>%s"
        "<form method='post'><textarea name='json'>%s</textarea>"
        "<div class='meta'>保存时自动压成单行 compact JSON（键顺序保持你在文本里的顺序，md5 会随顺序变）</div>"
        "<button type='submit'>保存并生效</button>"
        "<a href='/'>返回看板</a></form>"
        "<div class='meta'>生效方式：fsd_mock 热加载，车机下一次请求即用新载荷；不需要重启任何进程。</div>"
        "</div></body></html>" % (
            info["bytes"], info["md5"], info["fields"], badge, msg, html.escape(pretty)),
        mimetype="text/html; charset=utf-8")


def _tail(path: str, n: int = 5000) -> list:
    rows = []
    try:
        with open(path, encoding="utf-8", errors="replace") as fh:
            for line in fh:
                line = line.strip()
                if not line:
                    continue
                try:
                    rows.append(json.loads(line))
                except json.JSONDecodeError:
                    continue
    except OSError:
        return []
    return rows[-n:]


def _payload_info() -> dict:
    try:
        with open(PAYLOAD, "rb") as fh:
            raw = fh.read()
        obj = json.loads(raw.decode("utf-8"))
        return {"bytes": len(raw), "md5": hashlib.md5(raw).hexdigest(),
                "fields": len(obj), "json": obj}
    except (OSError, ValueError):
        return {"bytes": 0, "md5": "-", "fields": 0, "json": {}}


def _tcp_conns() -> list:
    now = time.time()
    if now - _CONN_CACHE["ts"] < 3.0:
        return _CONN_CACHE["rows"]
    out = []
    try:
        raw = subprocess.run(["netstat", "-ano", "-p", "TCP"],
                             capture_output=True, text=True, timeout=5,
                             creationflags=_NO_WIN).stdout
    except Exception:  # noqa: BLE001
        return out
    for line in raw.splitlines():
        parts = line.split()
        if len(parts) < 5 or parts[0].upper() != "TCP":
            continue
        local, remote, state = parts[1], parts[2], parts[3]
        if not local.endswith(":443") or remote.startswith("0.0.0.0") or remote.startswith("[::"):
            continue
        host = remote.rsplit(":", 1)[0].strip("[]")
        out.append({"remote": host, "port": remote.rsplit(":", 1)[-1],
                    "state": state, "car": host == CAR_IP})
    _CONN_CACHE["ts"] = now
    _CONN_CACHE["rows"] = out
    return out


def _arp_stats() -> dict:
    stats = {"poison": 0, "dns": 0, "redirect": 0, "fwd_l2": 0, "rst": 0, "error": 0}
    try:
        with open(ARP, encoding="utf-8", errors="replace") as fh:
            for line in fh:
                if "stats {" not in line:
                    continue
                m = re.search(r"stats (\{.*?\})", line)
                if not m:
                    continue
                try:
                    d = json.loads(m.group(1).replace("'", '"'))
                except json.JSONDecodeError:
                    continue
                for k in stats:
                    if isinstance(d.get(k), int):
                        stats[k] = d[k]
    except OSError:
        pass
    return stats


_PING_CACHE = {"ts": 0.0, "ok": False}


def _l2_alive(ip: str) -> bool:
    """车机在二层是否可达（ping 一次，缓存 10 秒；子进程不开窗口）。"""
    now = time.time()
    if now - _PING_CACHE["ts"] < 10:
        return _PING_CACHE["ok"]
    ok = False
    try:
        r = subprocess.run(["ping", "-n", "1", "-w", "800", ip],
                           capture_output=True, text=True, timeout=4,
                           creationflags=_NO_WIN)
        ok = r.returncode == 0
    except Exception:  # noqa: BLE001
        ok = False
    _PING_CACHE["ts"] = now
    _PING_CACHE["ok"] = ok
    return ok

def _maintain_car_recent() -> None:
    """把 hits.jsonl 里车机来源的请求回写到滚动文件，最多保留 999 条。"""
    try:
        if os.path.exists(CARREC) and os.path.getmtime(HITS) <= os.path.getmtime(CARREC):
            return
        rows = []
        with open(HITS, encoding="utf-8", errors="replace") as fh:
            for line in fh:
                if '"client": "192.168.' in line:
                    rows.append(line if line.endswith("\n") else line + "\n")
        with open(CARREC, "w", encoding="utf-8") as fh:
            fh.writelines(rows[-CAR_CAP:])
    except OSError:
        pass


def _handshake_rows(n: int = 8) -> list:
    rows = _tail(HSLOG, 500)
    out = []
    for r in rows[-n:]:
        ts = (r.get("ts") or "")
        age = None
        try:
            dt = datetime.strptime(ts[:19], "%Y-%m-%dT%H:%M:%S")
            age = int((datetime.now() - dt).total_seconds())
        except ValueError:
            pass
        out.append({"ts": ts, "age": age, "event": r.get("event"),
                    "client": r.get("client"), "sni": r.get("sni"),
                    "tls": r.get("tls"), "cipher": r.get("cipher"),
                    "first_request": r.get("first_request"),
                    "error": r.get("error")})
    return out

def car_state(hits: list, dns: list) -> dict:
    def last_ts(rows, key):
        best = None
        for r in rows:
            if (r.get(key) or "") in LOCAL_IPS or not r.get(key):
                continue
            s = (r.get("ts") or "")[:19]
            try:
                d = datetime.strptime(s, "%Y-%m-%dT%H:%M:%S")
            except ValueError:
                continue
            if best is None or d > best:
                best = d
        return best

    lh = last_ts(hits, "client")
    ld = last_ts(dns, "peer")
    cands = [x for x in (lh, ld) if x]
    last = max(cands) if cands else None
    idle = (datetime.now() - last).total_seconds() if last else None
    online = bool(idle is not None and idle < 180)
    return {
        "online": online,
        "l2": _l2_alive("192.168.199.95"),
        "idle": int(idle) if idle is not None else None,
        "last": last.strftime("%H:%M:%S") if last else None,
        "last_http": lh.strftime("%H:%M:%S") if lh else None,
        "last_dns": ld.strftime("%H:%M:%S") if ld else None,
    }

def _hit_age(intercepts: list) -> int | None:
    if not intercepts:
        return None
    try:
        dt = datetime.strptime((intercepts[-1].get("ts") or "")[:19], "%Y-%m-%dT%H:%M:%S")
        return int((datetime.now() - dt).total_seconds())
    except ValueError:
        return None


def build_state() -> dict:
    _maintain_car_recent()
    hits = _tail(HITS)
    dns = _tail(DNS, 20000)
    payload = _payload_info()
    car = [r for r in hits if r.get("client") and r["client"] not in LOCAL_IPS]
    intercepts = [r for r in car if r.get("kind") == "HIT" and "feature_configuration" in (r.get("url") or "")]
    vin = None
    for r in reversed(car):
        if r.get("vin"):
            vin = r["vin"]
            break
    if not vin:
        for r in reversed(car):
            m = re.search(r"/vehicles/([A-HJ-NPR-Z0-9]{17})/", r.get("url") or "")
            if m:
                vin = m.group(1)
                break
    paths = Counter()
    for r in car:
        m = re.match(r"https?://[^/]+(/[^?]*)", r.get("url") or "")
        if m:
            p = re.sub(r"/vehicles/[A-HJ-NPR-Z0-9]{17}/", "/vehicles/<VIN>/", m.group(1))
            paths[str(r.get("method") or "?") + " " + p] += 1
    apidns = [d for d in dns if "api-prd" in (d.get("q") or "") and (d.get("peer") or "") not in LOCAL_IPS]
    redirects = [d for d in apidns if str(d.get("action", "")).startswith("REDIRECT")]
    conns = [c for c in _tcp_conns() if c["car"]]
    return {
        "now": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
        "ip": CAR_IP, "mac": CAR_MAC, "vin": vin,
        "tls": bool(car),
        "http2": any((r.get("http_version") or "").startswith("HTTP/2") for r in car),
        "live_conn": len(conns),
        "decrypted": len(car),
        "intercepts": intercepts,
        "car_requests": len(car),
        "recent": car[-60:],
        "recent_total": len(car),
        "recent_cap": CAR_CAP,
        "paths": paths.most_common(12),
        "dns_api": len(apidns), "dns_redirect": len(redirects),
        "payload": payload,
        "car_status": car_state(hits, dns),
        "config_history": _config_history(),
        "last_hit_age": _hit_age(intercepts),
        "last_hit_bytes": (intercepts[-1].get("bytes") if intercepts else None),
        "last_hit_md5": (intercepts[-1].get("md5") if intercepts else None),
        "last_hit_ts": (intercepts[-1].get("ts") if intercepts else None),
        "handshakes": _handshake_rows(8),
        "car_conns": [c for c in _tcp_conns() if c["car"]],
        "arp": _arp_stats(),
    }


CSS = """
*{box-sizing:border-box}
body{margin:0;background:#0d1117;color:#e6edf3;font:14px/1.5 "Segoe UI",system-ui,sans-serif}
header{padding:12px 18px;border-bottom:1px solid #30363d;display:flex;gap:14px;align-items:center;flex-wrap:wrap}
h1{font-size:16px;margin:0}
.wrap{padding:16px 18px;max-width:1280px;margin:0 auto}
.grid{display:grid;grid-template-columns:repeat(auto-fit,minmax(180px,1fr));gap:10px;margin-bottom:14px}
.card{background:#161b22;border:1px solid #30363d;border-radius:8px;padding:10px 12px}
.k{color:#8b949e;font-size:12px}
.v{font-size:19px;font-weight:600;margin-top:3px;word-break:break-all}
.v.s{font-size:13px;font-weight:500}
section{background:#161b22;border:1px solid #30363d;border-radius:8px;margin-bottom:12px}
h2{font-size:12px;margin:0;padding:9px 12px;border-bottom:1px solid #30363d;color:#8b949e;font-weight:600}
table{width:100%;border-collapse:collapse;font-size:12.5px}
th,td{text-align:left;padding:6px 11px;border-bottom:1px solid #30363d;vertical-align:top}
th{color:#8b949e;font-weight:500;white-space:nowrap}
tr:last-child td{border-bottom:0}
code{font-family:Consolas,monospace;font-size:12px;color:#58a6ff;word-break:break-all}
.k.ok{color:#3fb950;font-weight:700}
.k.warn{color:#d29922;font-weight:700}
.k.bad{color:#f85149;font-weight:700}
.fx{position:fixed;inset:0;pointer-events:none;z-index:99;background:radial-gradient(circle at 50% 62%, rgba(248,81,73,.30), rgba(248,81,73,0) 62%);animation:fxpulse 1.1s ease-in-out infinite}
.fx .banner{position:absolute;top:16%;left:50%;transform:translateX(-50%);font:800 30px/1.2 "Segoe UI",system-ui,sans-serif;color:#ffd33d;text-shadow:0 0 10px #f85149,0 0 26px #ff6a00,0 0 48px #ff3b00;animation:fxzoom 1.1s ease-in-out infinite;white-space:nowrap}
.fx .sub{position:absolute;top:24%;left:50%;transform:translateX(-50%);font:600 14px/1.4 Consolas,monospace;color:#ffb86b}
.fx .f{position:absolute;bottom:-6vh;font-size:34px;animation:frise 2.2s linear infinite}
@keyframes fxpulse{0%,100%{opacity:.55}50%{opacity:1}}
@keyframes fxzoom{0%,100%{transform:translateX(-50%) scale(1)}50%{transform:translateX(-50%) scale(1.1)}}
@keyframes frise{0%{transform:translateY(0) scale(.6);opacity:0}15%{opacity:1}100%{transform:translateY(-70vh) scale(1.35);opacity:0}}
.card.ok{border-color:#238636;box-shadow:0 0 0 1px #238636 inset}
.card.warn{border-color:#d29922;box-shadow:0 0 0 1px #d29922 inset}
.card.bad{border-color:#f85149;box-shadow:0 0 0 1px #f85149 inset}
.badge{display:inline-block;padding:1px 7px;border-radius:10px;font-size:11px;border:1px solid #30363d}
.ok{color:#3fb950}.bad{color:#f85149}.warn{color:#d29922}.dim{color:#8b949e}
pre{margin:0;padding:11px 12px;overflow:auto;font-family:Consolas,monospace;font-size:12px;color:#a5d6ff;white-space:pre-wrap}
"""


def esc(v) -> str:
    return html.escape("" if v is None else str(v))


def render() -> str:
    s = build_state()
    p = s["payload"]
    hs = "握手：TLS1.3 + HTTP/2 已建立" if s["http2"] else ("握手：TLS 已建立" if s["tls"] else "握手：未建立")
    hs_cls = "ok" if s["tls"] else "dim"
    lk = ("连接：%d 条 Established" % s["live_conn"]) if s["live_conn"] else "连接：无"
    lk_cls = "ok" if s["live_conn"] else "dim"

    timeline = []
    for r in s["intercepts"]:
        timeline.append((r.get("ts") or "", "hit", r))
    last_md5 = None
    for r in s["config_history"]:
        if not r.get("bytes"):
            continue
        md5 = r.get("md5")
        if md5 and md5 == last_md5:      # 内容相同的连续保存只留一条，去掉重复点击噪声
            continue
        last_md5 = md5
        timeline.append((r.get("ts") or "", "cfg", r))
    timeline.sort(key=lambda x: x[0], reverse=True)

    int_rows = []
    for ts, kind, r in timeline[:20]:
        if kind == "hit":
            int_rows.append(
                "<tr><td>%s</td><td><span class=\"badge b-hit\">车机取配置</span> %s</td>"
                "<td><code>%s</code></td><td><code>%s</code><br>%s B</td>"
                "<td class=\"ok\">%s B / %s</td><td><code>%s</code></td><td>%s</td></tr>" % (
                    esc(ts), esc(r.get("method")), esc(r.get("vin")),
                    esc(r.get("req_head")), esc(r.get("req_bytes")),
                    esc(r.get("bytes")), esc(r.get("mode")),
                    esc((r.get("md5") or "")[:14]) + "...", esc(r.get("http_version"))))
        else:
            int_rows.append(
                "<tr><td>%s</td><td><span class=\"badge b-flow\">配置变更</span> %s</td>"
                "<td>%s 字段</td><td>—</td><td>%s B</td>"
                "<td><code>%s</code></td><td>本地保存</td></tr>" % (
                    esc(ts), esc(r.get("source")), esc(r.get("fields")),
                    esc(r.get("bytes")), esc((r.get("md5") or "")[:14]) + "..."))
    if not int_rows:
        int_rows = ["<tr><td colspan=\"7\" class=\"dim\">还没有记录</td></tr>"]

    # 最近请求：按「方法+路径（去查询串）」把连续重复项折叠成一条，避免一屏全是 vault_metadata
    collapsed = []
    for r in s["recent"][-40:]:
        url = r.get("url") or ""
        base = re.sub(r"\?.*$", "", re.sub(r"https?://[^/]+", "", url))
        key = "%s %s" % (r.get("method") or "", base)
        if collapsed and collapsed[-1]["key"] == key:
            collapsed[-1]["n"] += 1
            collapsed[-1]["ts"] = (r.get("ts") or "")[11:]
            collapsed[-1]["kind"] = r.get("kind") or collapsed[-1]["kind"]
        else:
            collapsed.append({"key": key, "method": r.get("method") or "", "path": base,
                              "query": ("?…" if "?" in url else ""),
                              "ts": (r.get("ts") or "")[11:], "n": 1,
                              "kind": r.get("kind") or ""})

    rec_rows = []
    for c in reversed(collapsed[-18:]):
        cls = "ok" if c["kind"] == "HIT" else "dim"
        times = ("×%d" % c["n"]) if c["n"] > 1 else ""
        rec_rows.append(
            "<tr><td>%s</td><td>%s</td><td><code>%s%s</code></td>"
            "<td>%s</td><td class=\"%s\">%s</td></tr>" % (
                esc(c["ts"]), esc(c["method"]), esc(c["path"]), esc(c["query"]),
                esc(times), cls, esc(c["kind"])))
    if not rec_rows:
        rec_rows = ["<tr><td colspan=\"5\" class=\"dim\">还没有车机请求</td></tr>"]

    path_rows = ["<tr><td><code>%s</code></td><td>%d</td></tr>" % (esc(k), v) for k, v in s["paths"]] or \
                ["<tr><td colspan=\"2\" class=\"dim\">-</td></tr>"]

    cfg_rows = []
    for r in reversed(s["config_history"]):
        cfg_rows.append("<tr><td>%s</td><td>%s</td><td>%s</td><td><code>%s</code></td><td>%s</td></tr>" % (
            esc(r.get("ts")), esc(r.get("source")), esc(r.get("bytes")),
            esc((r.get("md5") or "")[:14]) + "...", esc(r.get("fields"))))
    if not cfg_rows:
        cfg_rows = ["<tr><td colspan=\"5\" class=\"dim\">还没有配置变更记录</td></tr>"]

    a = s["arp"]
    last_int = s["intercepts"][-1]["ts"] if s["intercepts"] else "—"
    cs = s["car_status"]
    cs_card_cls = "ok" if cs["online"] else ("warn" if cs.get("l2") else "bad")
    cs_label = ("车机状态（在线）" if cs["online"]
                else ("车机状态（链路可达）" if cs.get("l2") else "车机状态（离线）"))
    if cs["online"]:
        cs_html = '<span class="ok">在线</span> · %d 秒前有请求' % cs["idle"]
    elif cs.get("l2"):
        cs_html = '<span class="warn">链路可达</span> · 无请求，最后 %s' % (cs["last"] or "无记录")
    else:
        cs_html = '<span class="bad">离线</span> · 最后活动 %s' % (cs["last"] or "无记录")

    # ---- 车机连接 & 握手区块 ----
    hs_list = s["handshakes"]
    car_conns = s["car_conns"]
    last_hs = None
    for h in reversed(hs_list):
        if h["event"] == "handshake_ok":
            last_hs = h
            break
    hs_live = bool(last_hs and last_hs["age"] is not None and last_hs["age"] <= 3)
    hs_age_txt = ("%d 秒前" % last_hs["age"]) if (last_hs and last_hs["age"] is not None) else "无记录"
    hs_time = (last_hs["ts"][11:19] if last_hs and last_hs.get("ts") else "—")
    conn_txt = ("已连接 · %d 条 Established" % len(car_conns)) if car_conns else "无活动连接"
    conn_cls = "ok" if car_conns else "dim"
    live_txt = ("有 · %s" % hs_age_txt) if hs_live else "无"
    live_cls = "ok" if hs_live else "dim"

    hs_rows = []
    for h in reversed(hs_list[-8:]):
        ev = h["event"] or ""
        if ev == "handshake_ok":
            badge = "<span class=\"badge b-hit\">握手成功</span>"
            detail = "%s / %s" % (esc(h["tls"] or "-"), esc(h["cipher"] or "-"))
        elif ev == "handshake_failed":
            badge = "<span class=\"badge\" style=\"color:#f85149;border-color:#f85149\">握手失败</span>"
            detail = esc(h["error"] or "-")
        else:
            badge = "<span class=\"badge b-flow\">ClientHello</span>"
            detail = esc(h["sni"] or "-")
        hs_rows.append(
            "<tr><td>%s</td><td>%s</td><td>%s</td><td><code>%s</code></td>"
            "<td><code>%s</code></td><td>%s</td></tr>" % (
                esc((h["ts"] or "")[11:19]), badge, esc((h["client"] or "")[:22]),
                esc(h["sni"] or "-"), esc(h["first_request"] or "-"), detail))
    if not hs_rows:
        hs_rows = ["<tr><td colspan=\"6\" class=\"dim\">还没有握手记录（车机尚未发起连接）</td></tr>"]

    hs_html = (
        "<section><h2>车机连接 &amp; 握手（页面每 2 秒刷新，绿色=最近 3 秒内的握手）</h2>"
        "<div class=\"grid\" style=\"padding:12px 12px 0\">"
        "<div class=\"card\"><div class=\"k\">连接状态</div><div class=\"v s %s\">%s</div></div>"
        "<div class=\"card\"><div class=\"k\">最后握手时间</div><div class=\"v s\">%s <span class=\"dim\">（%s）</span></div></div>"
        "<div class=\"card\"><div class=\"k\">最近 3 秒内握手</div><div class=\"v s %s\">%s</div></div>"
        "</div>"
        "<table><thead><tr><th>时间</th><th>事件</th><th>客户端</th><th>SNI</th><th>第一条请求</th><th>TLS / 详情</th></tr></thead>"
        "<tbody>%s</tbody></table></section>" % (
            conn_cls, conn_txt, hs_time, hs_age_txt, live_cls, live_txt, "".join(hs_rows)))

    # ---- 最后下发 + 成功后 20 秒烟花 ----
    hit_age = s["last_hit_age"]
    if hit_age is None:
        hit_txt = "—"
        hit_cls = "dim"
    elif hit_age < 60:
        hit_txt = "刚刚（%d 秒前）" % hit_age
        hit_cls = "ok"
    elif hit_age < 3600:
        hit_txt = "%d 分钟前" % (hit_age // 60)
        hit_cls = "ok"
    else:
        hit_txt = "%d 小时前" % (hit_age // 3600)
        hit_cls = "dim"

    fx_overlay = ""
    if hit_age is not None and 0 <= hit_age <= 20:
        flames = "".join(
            "<span class=\"f\" style=\"left:%d%%;animation-delay:%.1fs\">%s</span>" % (
                left, delay, "🔥")
            for left, delay in ((8, 0.0), (20, .4), (33, .8), (46, 1.2), (58, .2),
                                (70, .9), (82, 1.5), (93, .6)))
        fx_overlay = (
            "<div class=\"fx\">"
            "<div class=\"banner\">🎆 下发成功 🎆</div>"
            "<div class=\"sub\">feature_configuration · %s B · md5 %s…</div>%s</div>" % (
                esc(s["last_hit_bytes"]), esc((s["last_hit_md5"] or "")[:12]), flames))

    out = (
        "<!doctype html><html lang=\"zh-CN\"><head><meta charset=\"utf-8\">"
        "<meta http-equiv=\"X-UA-Compatible\" content=\"IE=edge\">"
        "<meta http-equiv=\"refresh\" content=\"2\">"
        "<title>FSD 拦截实况</title><style>" + CSS + "</style></head><body>"
        "<header><h1>FSD 拦截实况</h1>"
        "<a href=\"/config\" style=\"color:#1f6feb;font-weight:600;text-decoration:none;"
        "border:1px solid #1f6feb;padding:3px 10px;border-radius:6px\">填写配置</a>"
        "<span class=\"badge " + hs_cls + "\">" + hs + "</span>"
        "<span class=\"badge " + lk_cls + "\">" + lk + "</span>"
        "<span class=\"dim\">" + esc(s["now"]) + "</span></header>" +
        fx_overlay +
        "<div class=\"wrap\"><div class=\"grid\">"
        "<div class=\"card\"><div class=\"k\">拦截次数 feature_configuration</div><div class=\"v ok\">%d</div></div>" % len(s["intercepts"]) +
        "<div class=\"card\"><div class=\"k\">最后拦截时间</div><div class=\"v s\">" + esc(last_int) + "</div></div>"
        "<div class=\"card\"><div class=\"k\">车机 VIN</div><div class=\"v s\"><code>" + esc(s["vin"]) + "</code></div></div>"
        "<div class=\"card\"><div class=\"k\">当前载荷（下次生效）</div><div class=\"v s\">%d B / md5 %s...</div></div>" % (p["bytes"], esc(p["md5"][:10])) +
        "<div class=\"card " + cs_card_cls + "\"><div class=\"k " + cs_card_cls + "\">" + cs_label + "</div>"
        "<div class=\"v s\">__CARST__</div></div>"
        "<div class=\"card " + hit_cls + "\"><div class=\"k " + hit_cls + "\">最后下发成功</div><div class=\"v s\">" + hit_txt + "</div></div>" +
        "<div class=\"card\"><div class=\"k\">车机请求总数</div><div class=\"v\">%d</div></div>" +
        "<div class=\"card\"><div class=\"k\">api-prd DNS 重定向</div><div class=\"v s\">%d / %d 次查询</div></div>" % (s["dns_redirect"], s["dns_api"]) +
        "</div>" + hs_html +
        "<section><h2>下发时间线（配置变更 → 车机取配置）</h2><table><thead><tr>"
        "<th>时间</th><th>类型</th><th>VIN / 字段</th><th>车机上送</th><th>回包</th><th>md5</th><th>链路</th>"
        "</tr></thead><tbody>" + "".join(int_rows) + "</tbody></table></section>"
        "<section><h2>车机最近请求</h2><table><thead><tr><th>时间</th><th>方法</th><th>路径</th><th>重复</th><th>类型</th></tr></thead>"
        "<tbody>" + "".join(rec_rows) + "</tbody></table></section>"
        "<section><h2>接口调用分布</h2><table><thead><tr><th>接口</th><th>次数</th></tr></thead><tbody>" +
        "".join(path_rows) + "</tbody></table></section>"
        "<section><h2>配置变更记录（谁在什么时候改了下发字段）</h2><table><thead><tr>"
        "<th>时间</th><th>来源</th><th>字节</th><th>md5</th><th>字段数</th></tr></thead><tbody>" +
        "".join(cfg_rows) + "</tbody></table></section>"
        "<section><h2>当前回包载荷 · <code>" + esc(p["md5"]) + "</code></h2><pre>" +
        esc(json.dumps(p["json"], ensure_ascii=False, indent=2)) + "</pre></section>"
        "<section><h2>链路计数（ARP 引流）</h2><table><thead><tr><th>投毒帧</th><th>DNS 请求</th>"
        "<th>DNS 重定向</th><th>二层转发</th><th>RST</th><th>错误</th></tr></thead><tbody><tr>"
        "<td>%d</td><td>%d</td><td>%d</td><td>%d</td><td>%d</td><td class=\"%s\">%d</td>"
        "</tr></tbody></table></section></div></body></html>" % (
            a["poison"], a["dns"], a["redirect"], a["fwd_l2"], a["rst"],
            "bad" if a["error"] else "ok", a["error"])
    )
    return out.replace("__CARST__", cs_html)


@app.after_request
def _no_cache(resp):
    # 浏览器绝不缓存，保证 2 秒刷新拿到的都是最新渲染
    resp.headers["Cache-Control"] = "no-store, no-cache, must-revalidate, max-age=0"
    resp.headers["Pragma"] = "no-cache"
    resp.headers["Expires"] = "0"
    return resp


@app.route("/")
def index():
    return Response(render(), mimetype="text/html; charset=utf-8")


@app.route("/api/state")
def api_state():
    s = build_state()
    s.pop("payload", None)
    return jsonify(s)


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--host", default="127.0.0.1")
    ap.add_argument("--port", type=int, default=8900)
    args = ap.parse_args()
    print("[fsd_panel] http://%s:%d  logs=%s" % (args.host, args.port, LOGS), flush=True)
    app.run(host=args.host, port=args.port, threaded=True, debug=False, use_reloader=False)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

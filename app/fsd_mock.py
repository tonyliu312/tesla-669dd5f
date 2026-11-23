"""
fsd_mock.py — mitmproxy addon: 伪造 /feature_configuration 响应

命中任意路径里的 /feature_configuration -> 200 + 固定 JSON，并按 body 重算
    X-Checksum: md5(body).hexdigest()

两种接法：
  1) 车机走 HTTP 明文（mothership.vn.teslamotors.com:4567 / 网关改写前）——不用证书：
     mitmdump -s fsd_mock.py --mode reverse:http://<REAL_IP>:4567 \
              --listen-host 0.0.0.0 --listen-port 4567 --set keep_host_header=true
  2) 车机/网关走 HTTPS 且愿意装 mitmproxy CA（或可被代理）：
     mitmdump -s fsd_mock.py --mode regular@8080 --listen-host 0.0.0.0

环境变量（都可选）：
  FSD_MOCK=0                 关闭替换（默认开）
  FSD_MOCK_JSON=<path>       外部 JSON 覆盖 payload（自动压单行并重算 checksum）
  FSD_MOCK_HOSTS=a.com,b.com 只对这些 Host 生效（默认全部）
  FSD_MOCK_METHOD=POST       只对这些方法生效（默认全部）
  FSD_MOCK_LOG_DIR=<dir>     命中日志目录（默认 ./logs）
  FSD_MOCK_VERBOSE=1         把未命中的 feature* 请求也打出来
"""

from __future__ import annotations

import hashlib
import json
import os
import re
import time

from mitmproxy import ctx, http

# 车机侧期望的 9 个字段（compact JSON，282 字节）
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

PATH_RE = re.compile(r"/feature_configuration/?($|[?#])")
NEAR_MISS_RE = re.compile(r"feature", re.I)


def _compact(payload: dict) -> bytes:
    return json.dumps(payload, separators=(",", ":"), ensure_ascii=False).encode("utf-8")


class FsdMock:
    def __init__(self) -> None:
        self.payload = DEFAULT_PAYLOAD
        self.payload_path = os.environ.get("FSD_MOCK_JSON")
        self.payload_mtime = 0.0
        if self.payload_path:
            with open(self.payload_path, "r", encoding="utf-8") as fh:
                self.payload = json.load(fh)
            try:
                self.payload_mtime = os.path.getmtime(self.payload_path)
            except OSError:
                self.payload_mtime = 0.0

        self.body = _compact(self.payload)
        self.checksum = hashlib.md5(self.body).hexdigest()
        self.hosts = {h.strip().lower() for h in os.environ.get("FSD_MOCK_HOSTS", "").split(",") if h.strip()}
        self.methods = {m.strip().upper() for m in os.environ.get("FSD_MOCK_METHOD", "").split(",") if m.strip()}
        self.verbose = os.environ.get("FSD_MOCK_VERBOSE", "0") not in {"0", "false", "off"}
        self.log_all = os.environ.get("FSD_MOCK_LOG_ALL", "0") not in {"0", "false", "off"}
        self.log_dir = os.environ.get("FSD_MOCK_LOG_DIR", os.path.join(os.path.dirname(os.path.abspath(__file__)), "logs"))
        os.makedirs(self.log_dir, exist_ok=True)
        # 模式文件：{"mode":"reply"|"observe"}，不改文件即默认 reply；看板改它即时生效
        self.mode_path = os.environ.get("FSD_MOCK_MODE_FILE", os.path.join(os.path.dirname(os.path.abspath(__file__)), "mode.json"))
        self.mode = "reply"
        self.mode_mtime = 0.0
        self._load_mode(force=True)
        self.req_dir = os.path.join(self.log_dir, "requests")
        self._hs_seen: set[str] = set()
        self.ca_subject = ""
        try:
            from cryptography import x509 as _x509
            _ca = os.path.join(os.path.dirname(os.path.abspath(__file__)), "certs2", "mitmproxy-ca.pem")
            if os.path.exists(_ca):
                _pem = open(_ca, "rb").read()
                _first = _pem.split(b"-----END CERTIFICATE-----")[0] + b"-----END CERTIFICATE-----"
                self.ca_subject = _x509.load_pem_x509_certificate(_first).subject.rfc4514_string()
        except Exception:
            pass
        os.makedirs(self.req_dir, exist_ok=True)
        self.hits = 0
        self.near = 0

    # ---- mitmproxy hooks -------------------------------------------------
    def load(self, loader) -> None:
        loader.add_option(
            "fsd_mock",
            bool,
            os.environ.get("FSD_MOCK", "1") not in {"0", "false", "False", "off"},
            "启用 /feature_configuration 响应替换",
        )

    def running(self) -> None:
        ctx.log.info(
            f"[fsd_mock] {'ON' if ctx.options.fsd_mock else 'OFF'} | "
            f"{len(self.body)} bytes | md5={self.checksum} | "
            f"hosts={','.join(sorted(self.hosts)) or '*'} | "
            f"methods={','.join(sorted(self.methods)) or '*'} | mode={self.mode} | log={self.log_dir}"
        )

    # ---- helpers ---------------------------------------------------------
    def _hosts_of(self, flow: http.HTTPFlow) -> set[str]:
        out = {flow.request.host.lower()}
        raw = flow.request.headers.get("host", "")
        if raw:
            out.add(raw.split(":", 1)[0].strip().lower())
        return out

    def _log(self, name: str, flow: http.HTTPFlow, extra: dict | None = None) -> None:
        rec = {
            "ts": time.strftime("%Y-%m-%dT%H:%M:%S%z"),
            "kind": name,
            "method": flow.request.method,
            "url": flow.request.pretty_url,
            "client": flow.client_conn.peername[0] if flow.client_conn.peername else None,
            "http_version": flow.request.http_version,
            "host_header": flow.request.headers.get("host", ""),
            "user_agent": flow.request.headers.get("user-agent", ""),
        }
        if extra:
            rec.update(extra)
        try:
            with open(os.path.join(self.log_dir, "hits.jsonl"), "a", encoding="utf-8") as fh:
                fh.write(json.dumps(rec, ensure_ascii=False) + "\n")
        except OSError:
            pass

    def _hit(self, flow: http.HTTPFlow) -> bool:
        if not ctx.options.fsd_mock:
            return False
        if not PATH_RE.search(flow.request.path):
            return False
        if self.hosts and not (self.hosts & self._hosts_of(flow)):
            return False
        if self.methods and flow.request.method.upper() not in self.methods:
            return False
        return True

    # ---- main hook -------------------------------------------------------
    def _load_mode(self, force: bool = False) -> None:
        p = self.mode_path
        if not p:
            return
        try:
            mtime = os.path.getmtime(p)
        except OSError:
            return
        if not force and mtime == self.mode_mtime:
            return
        try:
            with open(p, "r", encoding="utf-8") as fh:
                data = json.load(fh)
            mode = str((data or {}).get("mode", "reply")).lower()
        except (OSError, ValueError, AttributeError):
            return
        if mode not in {"reply", "observe"}:
            return
        if mode != self.mode:
            ctx.log.warn(f"[fsd_mock] mode -> {mode}")
        self.mode = mode
        self.mode_mtime = mtime

    def _capture(self, flow: http.HTTPFlow) -> dict:
        """把车机这条请求原样记下来：方法/头/body 长度/md5/VIN，body 落盘。"""
        body = flow.request.content or b""
        ctype = flow.request.headers.get("content-type", "")
        vin = ""
        m = re.search(r"/vehicles/([^/?#]+)", flow.request.path)
        if m:
            vin = m.group(1)
        info = {
            "req_bytes": len(body),
            "req_md5": hashlib.md5(body).hexdigest() if body else "",
            "req_ctype": ctype[:80],
            "vin": vin,
            "mode": self.mode,
        }
        if body:
            name = f"{time.strftime('%Y%m%d-%H%M%S')}-{info['req_md5'][:8]}.bin"
            try:
                with open(os.path.join(self.req_dir, name), "wb") as fh:
                    fh.write(body)
                info["req_file"] = name
                head = body[:256]
                info["req_head"] = head.decode("utf-8", "replace") if (
                    "json" in ctype or "text" in ctype or head[:1] in (b"{", b"[")
                ) else head.hex()
            except OSError:
                pass
        return info

    def _maybe_reload(self) -> None:
        """payload.json 被 WEB 面板改过就热加载，不用重启 mitmproxy。"""
        p = self.payload_path
        if not p:
            return
        try:
            mtime = os.path.getmtime(p)
        except OSError:
            return
        if mtime == self.payload_mtime:
            return
        try:
            with open(p, "r", encoding="utf-8") as fh:
                payload = json.load(fh)
            if not isinstance(payload, dict):
                return
        except (OSError, ValueError):
            return
        self.payload_mtime = mtime
        self.payload = payload
        self.body = _compact(payload)
        self.checksum = hashlib.md5(self.body).hexdigest()
        ctx.log.warn(f"[fsd_mock] payload reloaded -> {len(self.body)}B, md5={self.checksum}")

    def request(self, flow: http.HTTPFlow) -> None:
        # 每条新连接第一次请求时记一次握手成功（此刻 tls_version/cipher/cert 都已就绪）
        try:
            cc = flow.client_conn
            key = "%s|%s" % (getattr(cc, "id", ""), getattr(cc, "peername", ""))
            if key not in self._hs_seen:
                self._hs_seen.add(key)
                issuer = subj = None
                try:
                    certs = getattr(cc, "certificate_list", None) or []
                    if certs:
                        from cryptography import x509
                        c = x509.load_der_x509_certificate(certs[0])
                        issuer = c.issuer.rfc4514_string()
                        subj = c.subject.rfc4514_string()
                except Exception:
                    pass
                alpn = getattr(cc, "alpn", None)
                self._hs({
                    "ts": time.strftime("%Y-%m-%dT%H:%M:%S%z"),
                    "event": "handshake_ok",
                    "client": str(getattr(cc, "peername", "") or ""),
                    "sni": getattr(cc, "sni", None),
                    "alpn": alpn.decode() if isinstance(alpn, bytes) else alpn,
                    "tls": getattr(cc, "tls_version", None),
                    "cipher": getattr(cc, "cipher", None),
                    "confdir": "certs2",
                    "first_request": "%s %s" % (flow.request.method, flow.request.path),
                })
        except Exception:
            pass

        self._maybe_reload()
        self._load_mode()
        if self.log_all:
            self._log("FLOW", flow, {"sni": getattr(flow.client_conn, "sni", None)})

        if self._hit(flow):
            info = self._capture(flow)   # 先看清车机发了什么
            if self.mode == "observe":
                # 只记录不回包：请求照常走上游
                self._log("OBSERVE", flow, info)
                ctx.log.warn(f"[fsd_mock] OBSERVE-only {flow.request.method} {flow.request.pretty_url} "
                             f"({info['req_bytes']}B)")
                return

            self.hits += 1
            # 然后才回包（短路，不访问上游）
            flow.response = http.Response.make(
                200,
                self.body,
                {
                    "Content-Type": "application/json",
                    "X-Checksum": self.checksum,
                    "Cache-Control": "no-store",
                },
            )
            self._log("HIT", flow, {**info, "bytes": len(self.body), "md5": self.checksum})
            ctx.log.warn(
                f"[fsd_mock] HIT #{self.hits} {flow.request.method} {flow.request.pretty_url} "
                f"vin={info['vin'] or '-'} req={info['req_bytes']}B -> 200, {len(self.body)}B, "
                f"X-Checksum={self.checksum}"
            )
            return

        if self.verbose and NEAR_MISS_RE.search(flow.request.path):
            self.near += 1
            self._log("NEAR_MISS", flow)
            ctx.log.info(f"[fsd_mock] near-miss {flow.request.method} {flow.request.pretty_url}")


    # ---------------- 握手观测（真实车机每次建 TLS 都会记一行） ----------------
    def _hs(self, rec: dict) -> None:
        try:
            with open(os.path.join(self.log_dir, "handshake.log"), "a", encoding="utf-8") as fh:
                fh.write(json.dumps(rec, ensure_ascii=False) + "\n")
        except OSError:
            pass

    def tls_clienthello(self, data) -> None:
        try:
            ci = getattr(data, "client_hello", None)
            peer = getattr(getattr(data, "context", None), "client", None)
            self._hs({
                "ts": time.strftime("%Y-%m-%dT%H:%M:%S%z"),
                "event": "clienthello",
                "client": str(getattr(peer, "peername", "") or ""),
                "sni": getattr(ci, "sni", None),
                "alpn": list(getattr(ci, "alpn_protocols", None) or []),
            })
        except Exception:
            pass

    def tls_failed_client(self, data) -> None:
        try:
            ctxc = getattr(data, "context", None)
            client = getattr(ctxc, "client", None)
            self._hs({
                "ts": time.strftime("%Y-%m-%dT%H:%M:%S%z"),
                "event": "handshake_failed",
                "client": str(getattr(client, "peername", "") or ""),
                "error": repr(getattr(data, "error", None)),
            })
        except Exception:
            pass

addons = [FsdMock()]

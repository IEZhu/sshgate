#!/usr/bin/env python3
"""sshgate - grant your current IP temporary firewall access after a secret URL + TOTP.

The secret, unguessable URL path is enforced by the fronting web server (e.g. nginx).
This service renders a small page, verifies a TOTP (RFC 6238) second factor, and - on
success - calls a privileged helper that opens the port for the caller's IP.

Pure standard library. Runs unprivileged, bound to localhost, behind a reverse proxy
that passes the real client IP in the ``X-Real-Client`` header.
"""
import base64
import hashlib
import hmac
import html
import ipaddress
import json
import struct
import subprocess
import threading
import time
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import parse_qs, urlsplit

CONFIG_PATH = "/etc/sshgate/config.json"

DEFAULTS = {
    "listen_host": "127.0.0.1",
    "listen_port": 8787,
    "open_helper": "/usr/local/sbin/sshgate-open",
    "logfile": "/var/log/sshgate/access.log",
    "max_fails": 5,        # failed codes per window (per IP) before a temporary lockout
    "fail_window": 900,    # seconds
    "default_lang": "en",
    "hold_hours": 24,      # informational only; the helper/reaper enforce the real hold
}


def load_config():
    cfg = dict(DEFAULTS)
    with open(CONFIG_PATH) as fh:
        cfg.update(json.load(fh))
    if not cfg.get("totp_secret"):
        raise SystemExit("config: 'totp_secret' is required")
    return cfg


CFG = load_config()
TOTP_SECRET = CFG["totp_secret"]

# --------------------------------------------------------------------------- i18n
# To add a language: add one entry below with the same set of keys. Nothing else.
TRANSLATIONS = {
    "en": {
        "title": "Open SSH",
        "hint": "Enter the 6-digit code from your authenticator app",
        "button": "Open for {h}h",
        "ok": "Access opened for {ip} for {h}h. You can connect over SSH now.",
        "bad": "Wrong code.",
        "locked": "Too many attempts. Try again in 15 minutes.",
        "error": "Code accepted, but opening the firewall failed (check server logs).",
        "your_ip": "Your IP: {ip}",
    },
    "ru": {
        "title": "Открыть SSH",
        "hint": "Введите 6-значный код из приложения-аутентификатора",
        "button": "Открыть на {h}ч",
        "ok": "Доступ открыт для {ip} на {h}ч. Теперь можно подключаться по SSH.",
        "bad": "Неверный код.",
        "locked": "Слишком много попыток. Подождите 15 минут.",
        "error": "Код верный, но открыть фаервол не удалось (см. логи сервера).",
        "your_ip": "Ваш IP: {ip}",
    },
    "es": {
        "title": "Abrir SSH",
        "hint": "Introduce el código de 6 dígitos de tu autenticador",
        "button": "Abrir por {h}h",
        "ok": "Acceso abierto para {ip} durante {h}h. Ya puedes conectarte por SSH.",
        "bad": "Código incorrecto.",
        "locked": "Demasiados intentos. Vuelve a intentarlo en 15 minutos.",
        "error": "Código correcto, pero no se pudo abrir el firewall (revisa los registros).",
        "your_ip": "Tu IP: {ip}",
    },
}


def pick_lang(headers, query):
    """Choose UI language: ?lang= override, then Accept-Language, then config default."""
    forced = parse_qs(query).get("lang", [""])[0].lower()
    if forced in TRANSLATIONS:
        return forced
    for chunk in headers.get("Accept-Language", "").split(","):
        code = chunk.split(";")[0].strip().lower()[:2]
        if code in TRANSLATIONS:
            return code
    default = CFG.get("default_lang", "en")
    return default if default in TRANSLATIONS else "en"


# --------------------------------------------------------------------------- TOTP
def totp(now, step=30, digits=6):
    key = base64.b32decode(TOTP_SECRET, casefold=True)
    counter = struct.pack(">Q", int(now // step))
    digest = hmac.new(key, counter, hashlib.sha1).digest()
    offset = digest[-1] & 0x0F
    value = (struct.unpack(">I", digest[offset:offset + 4])[0] & 0x7FFFFFFF) % (10 ** digits)
    return str(value).zfill(digits)


def verify_totp(code):
    code = (code or "").strip()
    if not (code.isdigit() and len(code) == 6):
        return False
    now = time.time()
    return any(hmac.compare_digest(totp(now + drift), code) for drift in (-30, 0, 30))


# ------------------------------------------------------------------- rate limiting
_lock = threading.Lock()
_fails = {}


def is_locked(ip):
    now = time.time()
    with _lock:
        recent = [t for t in _fails.get(ip, []) if now - t < CFG["fail_window"]]
        _fails[ip] = recent
        return len(recent) >= CFG["max_fails"]


def record_fail(ip):
    with _lock:
        _fails.setdefault(ip, []).append(time.time())


def clear_fails(ip):
    with _lock:
        _fails.pop(ip, None)


def client_ip(handler):
    ip = handler.headers.get("X-Real-Client", "").strip()
    try:
        ipaddress.ip_address(ip)
        return ip
    except ValueError:
        return None


def log(message):
    try:
        with open(CFG["logfile"], "a") as fh:
            fh.write(time.strftime("%Y-%m-%dT%H:%M:%S%z ") + message + "\n")
    except OSError:
        pass


# --------------------------------------------------------------------------- HTML
PAGE = """<!doctype html><html lang="__LANG__"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1"><title>__TITLE__</title><style>
body{font-family:system-ui,-apple-system,sans-serif;background:#0f1115;color:#e6e6e6;display:flex;min-height:100vh;align-items:center;justify-content:center;margin:0}
.card{background:#171a21;padding:32px;border-radius:12px;max-width:340px;width:90%;box-shadow:0 10px 30px rgba(0,0,0,.45)}
h1{font-size:18px;margin:0 0 6px}
p.hint{color:#9aa0aa;font-size:13px;margin:0 0 18px}
input{width:100%;box-sizing:border-box;padding:12px;font-size:22px;letter-spacing:6px;text-align:center;border-radius:8px;border:1px solid #333;background:#0f1115;color:#fff;margin-bottom:12px}
button{width:100%;padding:12px;font-size:16px;border:0;border-radius:8px;background:#2b6cff;color:#fff;cursor:pointer}
.msg{margin-top:14px;font-size:14px;min-height:18px}.ok{color:#4ade80}.err{color:#f87171}
.ip{color:#8b909a;font-size:12px;margin-top:16px}
.langs{margin-top:16px;font-size:12px}.langs a{color:#6b7280;margin:0 4px;text-decoration:none}
</style></head><body><div class="card">
<h1>🔐 __TITLE__</h1><p class="hint">__HINT__</p>
<form method="post" action="verify">
<input name="code" inputmode="numeric" autocomplete="one-time-code" maxlength="6" placeholder="000000" autofocus>
<button type="submit">__BUTTON__</button></form>
<div class="msg __CLS__">__MSG__</div>
<div class="ip">__YOUR_IP__</div>
<div class="langs">__LANGS__</div>
</div></body></html>"""


def render(lang, ip, cls="", msg=""):
    t = TRANSLATIONS[lang]
    hold = CFG["hold_hours"]
    langs = " · ".join('<a href="?lang=%s">%s</a>' % (c, c.upper()) for c in TRANSLATIONS)
    return (PAGE
            .replace("__LANG__", lang)
            .replace("__TITLE__", html.escape(t["title"]))
            .replace("__HINT__", html.escape(t["hint"]))
            .replace("__BUTTON__", html.escape(t["button"].format(h=hold)))
            .replace("__CLS__", cls)
            .replace("__MSG__", msg)
            .replace("__YOUR_IP__", html.escape(t["your_ip"].format(ip=ip)))
            .replace("__LANGS__", langs))


class Handler(BaseHTTPRequestHandler):
    server_version = "sshgate"
    protocol_version = "HTTP/1.1"

    def _send(self, status, body):
        payload = body.encode()
        self.send_response(status)
        self.send_header("Content-Type", "text/html; charset=utf-8")
        self.send_header("Content-Length", str(len(payload)))
        self.send_header("Referrer-Policy", "no-referrer")
        self.send_header("Cache-Control", "no-store")
        self.end_headers()
        self.wfile.write(payload)

    def do_GET(self):
        parts = urlsplit(self.path)
        if parts.path == "/":
            lang = pick_lang(self.headers, parts.query)
            self._send(200, render(lang, client_ip(self) or "?"))
        else:
            self._send(404, "not found")

    def do_POST(self):
        parts = urlsplit(self.path)
        if parts.path != "/verify":
            self._send(404, "not found")
            return
        lang = pick_lang(self.headers, parts.query)
        t = TRANSLATIONS[lang]
        ip = client_ip(self)
        if not ip:
            self._send(400, "bad request")
            return
        if is_locked(ip):
            log("locked " + ip)
            self._send(429, render(lang, ip, "err", html.escape(t["locked"])))
            return
        length = int(self.headers.get("Content-Length", 0) or 0)
        body = self.rfile.read(min(length, 4096)).decode("utf-8", "replace")
        code = parse_qs(body).get("code", [""])[0]
        if not verify_totp(code):
            record_fail(ip)
            log("fail " + ip)
            self._send(401, render(lang, ip, "err", html.escape(t["bad"])))
            return
        clear_fails(ip)
        try:
            subprocess.run(["sudo", "-n", CFG["open_helper"], ip],
                           check=True, timeout=15, capture_output=True)
            log("open " + ip)
            msg = html.escape(t["ok"].format(ip=ip, h=CFG["hold_hours"]))
            self._send(200, render(lang, ip, "ok", msg))
        except Exception as exc:  # report any failure to the log, generic message to client
            log("open-failed %s %r" % (ip, exc))
            self._send(500, render(lang, ip, "err", html.escape(t["error"])))

    def log_message(self, *args):
        return  # keep quiet: do not echo request paths


def main():
    server = ThreadingHTTPServer((CFG["listen_host"], int(CFG["listen_port"])), Handler)
    server.serve_forever()


if __name__ == "__main__":
    main()

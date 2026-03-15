#!/usr/bin/env python3
import json
import time
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import parse_qs


LOGIN_PAGE = """<!doctype html>
<html lang="en">
<head>
  <meta charset="utf-8">
  <title>Edge Gateway Control Panel</title>
  <meta name="viewport" content="width=device-width, initial-scale=1">
  <style>
    body { font-family: Arial, sans-serif; background: #eef2f5; margin: 0; }
    .wrap { max-width: 420px; margin: 8vh auto; background: white; border-radius: 8px; box-shadow: 0 8px 28px rgba(0,0,0,0.15); padding: 28px; }
    h1 { margin: 0 0 8px; font-size: 22px; color: #213547; }
    p { margin: 0 0 18px; color: #5a6470; }
    label { display: block; margin: 14px 0 6px; font-size: 13px; color: #334155; }
    input { width: 100%; padding: 10px; border: 1px solid #cbd5e1; border-radius: 6px; box-sizing: border-box; }
    button { width: 100%; margin-top: 18px; background: #1d4ed8; color: white; border: 0; padding: 11px; border-radius: 6px; font-weight: bold; cursor: pointer; }
    .note { margin-top: 14px; font-size: 12px; color: #64748b; }
  </style>
</head>
<body>
  <div class="wrap">
    <h1>Gateway Administration</h1>
    <p>Restricted management interface for branch edge devices.</p>
    <form method="post" action="/login">
      <label for="username">Username</label>
      <input id="username" name="username" autocomplete="username">
      <label for="password">Password</label>
      <input id="password" name="password" type="password" autocomplete="current-password">
      <button type="submit">Sign In</button>
    </form>
    <div class="note">Firmware: EG-OS 4.8.13 | Build 2026.02-LTS</div>
  </div>
</body>
</html>"""


def emit(payload):
    print(json.dumps(payload), flush=True)


class AdminHandler(BaseHTTPRequestHandler):
    server_version = "EdgeGateway/4.8"

    def log_message(self, format, *args):
        emit(
            {
                "service": "HTTP",
                "src_ip": self.client_address[0],
                "method": getattr(self, "command", ""),
                "path": getattr(self, "path", ""),
                "status": args[1] if len(args) > 1 else "",
                "user_agent": self.headers.get("User-Agent", ""),
                "eventid": "http.request",
            }
        )

    def _send_html(self, status_code, body):
        content = body.encode("utf-8")
        self.send_response(status_code)
        self.send_header("Content-Type", "text/html; charset=utf-8")
        self.send_header("Content-Length", str(len(content)))
        self.send_header("Set-Cookie", f"EGSESSID={int(time.time())}; HttpOnly")
        self.end_headers()
        self.wfile.write(content)

    def do_GET(self):
        if self.path in ["/", "/login", "/admin", "/admin/login.php", "/manager/html"]:
            self._send_html(200, LOGIN_PAGE)
            return

        self._send_html(404, "<h1>404</h1>")

    def do_POST(self):
        length = int(self.headers.get("Content-Length", "0"))
        raw = self.rfile.read(length).decode("utf-8", errors="ignore")
        form = parse_qs(raw)
        username = form.get("username", [""])[0]
        password = form.get("password", [""])[0]

        emit(
            {
                "service": "HTTP",
                "src_ip": self.client_address[0],
                "username": username,
                "password": password,
                "path": self.path,
                "user_agent": self.headers.get("User-Agent", ""),
                "eventid": "http.login_attempt",
            }
        )

        body = """<html><body><h1>Authentication failed</h1><p>Directory backend timed out.</p></body></html>"""
        self._send_html(403, body)


if __name__ == "__main__":
    server = ThreadingHTTPServer(("0.0.0.0", 8080), AdminHandler)
    emit({"service": "HTTP", "eventid": "http.server_start", "listen": "0.0.0.0:8080"})
    server.serve_forever()

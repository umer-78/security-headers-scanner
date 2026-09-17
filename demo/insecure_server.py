"""A deliberately unhardened local server, so the scanner has something to grade.

    python demo/insecure_server.py &      # serves on http://127.0.0.1:8000
    headerscan http://127.0.0.1:8000

Pass --secure to serve the hardened version and watch the grade go from F to B.
B rather than A because a local demo is plain HTTP, and HTTP alone costs 20 points.
"""

from __future__ import annotations

import argparse
from http.server import BaseHTTPRequestHandler, HTTPServer

SECURE_HEADERS = {
    "Strict-Transport-Security": "max-age=63072000; includeSubDomains; preload",
    "Content-Security-Policy": "default-src 'self'; frame-ancestors 'none'; object-src 'none'",
    "X-Content-Type-Options": "nosniff",
    "X-Frame-Options": "DENY",
    "Referrer-Policy": "strict-origin-when-cross-origin",
    "Permissions-Policy": "camera=(), microphone=(), geolocation=()",
}
PAGE = b"<!doctype html><title>demo</title><h1>Security header demo</h1>"


def handler(secure: bool):
    class Handler(BaseHTTPRequestHandler):
        server_version = "demo-server" if secure else "demo-server/1.2.3"
        sys_version = ""

        def version_string(self) -> str:
            return self.server_version

        def do_GET(self) -> None:
            self.send_response(200)
            self.send_header("Content-Type", "text/html; charset=utf-8")
            if secure:
                for k, v in SECURE_HEADERS.items():
                    self.send_header(k, v)
                self.send_header("Set-Cookie", "sid=abc; Secure; HttpOnly; SameSite=Lax; Path=/")
            else:
                self.send_header("X-Powered-By", "PHP/7.4.3")
                self.send_header("Set-Cookie", "PHPSESSID=abc; Path=/")
            self.end_headers()
            self.wfile.write(PAGE)

        def log_message(self, *args) -> None:
            pass

    return Handler


if __name__ == "__main__":
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--port", type=int, default=8000)
    ap.add_argument("--secure", action="store_true", help="serve the hardened version")
    args = ap.parse_args()
    srv = HTTPServer(("127.0.0.1", args.port), handler(args.secure))
    print(f"serving {'hardened' if args.secure else 'insecure'} demo on http://127.0.0.1:{args.port}")
    srv.serve_forever()

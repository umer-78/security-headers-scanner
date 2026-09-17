import json
import threading
from email.message import Message
from http.server import BaseHTTPRequestHandler, HTTPServer

import pytest

from headerscan import evaluate
from headerscan.cli import main
from headerscan.fetch import FetchError, fetch_headers

GOOD = {
    "Strict-Transport-Security": "max-age=63072000; includeSubDomains; preload",
    "Content-Security-Policy": "default-src 'self'; frame-ancestors 'none'; object-src 'none'",
    "X-Content-Type-Options": "nosniff",
    "X-Frame-Options": "DENY",
    "Referrer-Policy": "strict-origin-when-cross-origin",
    "Permissions-Policy": "camera=(), microphone=()",
}


def msg(headers: dict, cookies=()) -> Message:
    m = Message()
    for k, v in headers.items():
        m[k] = v
    for c in cookies:
        m["Set-Cookie"] = c
    return m


def test_hardened_site_gets_A():
    r = evaluate("https://example.com/", 200, msg(GOOD))
    assert r.grade == "A" and r.score == 100
    assert r.findings == []


def test_bare_https_site_fails():
    r = evaluate("https://example.com/", 200, msg({}))
    headers = {f.header for f in r.findings}
    assert {"Strict-Transport-Security", "Content-Security-Policy", "X-Frame-Options"} <= headers
    assert r.grade == "F"


def test_plain_http_is_high_severity():
    r = evaluate("http://example.com/", 200, msg(GOOD))
    assert r.findings[0].severity == "high" and r.findings[0].header == "(transport)"


def test_weak_csp_and_short_hsts():
    h = dict(GOOD)
    h["Content-Security-Policy"] = "script-src 'self' 'unsafe-inline' https:; frame-ancestors 'self'"
    h["Strict-Transport-Security"] = "max-age=300"
    msgs = [f.message for f in evaluate("https://x.test", 200, msg(h)).findings]
    assert any("unsafe-inline" in m for m in msgs)
    assert any("any host" in m for m in msgs)
    assert any("180 days" in m for m in msgs)


def test_nonce_makes_unsafe_inline_acceptable():
    h = dict(GOOD)
    h["Content-Security-Policy"] = "script-src 'self' 'unsafe-inline' 'nonce-abc'; frame-ancestors 'self'"
    assert evaluate("https://x.test", 200, msg(h)).grade == "A"


def test_version_disclosure_and_cookies():
    h = dict(GOOD, Server="nginx/1.18.0", **{"X-Powered-By": "PHP/7.4.3"})
    r = evaluate("https://x.test", 200, msg(h, ["PHPSESSID=abc; path=/", "theme=dark; Secure; HttpOnly; SameSite=Lax"]))
    found = [(f.header, f.severity) for f in r.findings]
    assert ("Server", "low") in found and ("X-Powered-By", "low") in found
    assert ("Set-Cookie", "medium") in found  # session cookie without flags
    assert sum(1 for f in r.findings if f.header == "Set-Cookie") == 1


def test_frame_ancestors_replaces_xfo():
    h = dict(GOOD)
    del h["X-Frame-Options"]
    assert not any(f.header == "X-Frame-Options" for f in evaluate("https://x.test", 200, msg(h)).findings)


class Handler(BaseHTTPRequestHandler):
    server_version = "demo/2.1"
    sys_version = ""

    def version_string(self):
        return self.server_version

    def do_GET(self):
        self.send_response(404 if self.path == "/missing" else 200)
        self.send_header("X-Content-Type-Options", "nosniff")
        self.end_headers()
        self.wfile.write(b"ok")

    def log_message(self, *a):
        pass


@pytest.fixture(scope="module")
def server():
    srv = HTTPServer(("127.0.0.1", 0), Handler)
    threading.Thread(target=srv.serve_forever, daemon=True).start()
    yield f"http://127.0.0.1:{srv.server_port}"
    srv.shutdown()


def test_fetch_real_server_including_error_status(server):
    url, status, headers = fetch_headers(server + "/missing")
    assert status == 404 and headers["Server"] == "demo/2.1"


def test_fetch_errors():
    with pytest.raises(FetchError):
        fetch_headers("ftp://example.com")
    with pytest.raises(FetchError):
        fetch_headers("http://127.0.0.1:1", timeout=2)


def test_cli_json_and_fail_under(server, capsys):
    assert main([server, "--json", "--fail-under", "F"]) == 0
    data = json.loads(capsys.readouterr().out)
    assert data[0]["grade"] == "F" and data[0]["status"] == 200
    assert main([server, "--fail-under", "C"]) == 1
    assert main(["http://127.0.0.1:1", "--timeout", "2"]) == 2

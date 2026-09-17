# headerscan: HTTP security header grader

[![CI](https://github.com/umer-78/security-headers-scanner/actions/workflows/ci.yml/badge.svg)](https://github.com/umer-78/security-headers-scanner/actions/workflows/ci.yml)
![Python](https://img.shields.io/badge/python-3.10%2B-blue)
![License](https://img.shields.io/badge/license-MIT-green)

A command-line tool that fetches a page, grades its **HTTP security headers and
cookies** from A to F, and says exactly which header to add or change. It runs
in CI too: fail a deploy when the grade drops.

It sends **one ordinary GET request** per URL, the same as a browser visit.
Only scan sites you own or are allowed to test.

```text
$ python -m http.server 8000 &     # a bare local test server
$ headerscan http://127.0.0.1:8000
http://127.0.0.1:8000  (HTTP 200)
  Grade F  ·  score 35/100
  HIGH   (transport): The site was served over plain HTTP.
         fix → Serve everything over HTTPS and redirect HTTP to it.
  MEDIUM Content-Security-Policy: No enforced Content-Security-Policy.
         fix → Start with: default-src 'self'; frame-ancestors 'self'; object-src 'none'
  MEDIUM X-Content-Type-Options: X-Content-Type-Options: nosniff is not set.
         fix → X-Content-Type-Options: nosniff
  MEDIUM X-Frame-Options: The page can be framed by any site (clickjacking).
         fix → X-Frame-Options: DENY, or CSP frame-ancestors 'self'
  LOW    Referrer-Policy: Referrer-Policy is not set.
         fix → Referrer-Policy: strict-origin-when-cross-origin
  LOW    Permissions-Policy: Permissions-Policy is not set.
         fix → Permissions-Policy: camera=(), microphone=(), geolocation=()
  LOW    Server: Server reveals a software version ('SimpleHTTP/0.6 Python/3.11.15').
         fix → Remove the version from the Server header.
```

## What it checks

| Check | Severity if missing or weak |
|---|---|
| HTTPS in use | high |
| `Strict-Transport-Security` (and `max-age` ≥ 180 days) | high / low |
| `Content-Security-Policy`: present, no `unsafe-inline` without nonces, no wildcard script hosts, `unsafe-eval` | medium / low |
| `X-Content-Type-Options: nosniff` | medium |
| Clickjacking: `X-Frame-Options` or CSP `frame-ancestors` | medium |
| `Referrer-Policy` present and not leaky | low |
| `Permissions-Policy` | low |
| Version numbers in `Server`, `X-Powered-By`, `X-AspNet-Version` | low |
| Cookies: `Secure`, `HttpOnly`, `SameSite` (medium for session-like names) | medium / low |

Score = 100 − 20 per high − 10 per medium − 5 per low.
Grades: **A** ≥ 90, **B** ≥ 80, **C** ≥ 65, **D** ≥ 50, else **F**.

## Install and run

```bash
git clone https://github.com/umer-78/security-headers-scanner.git
cd security-headers-scanner
python -m venv .venv && source .venv/bin/activate
pip install -e ".[dev]"

headerscan https://your-site.example
headerscan https://a.example https://b.example --json > report.json
headerscan https://staging.example --fail-under B      # exit 1 below B
```

Exit codes: `0` OK, `1` a grade is below `--fail-under`, `2` a URL could not be fetched.

## In GitHub Actions

```yaml
- run: pip install git+https://github.com/umer-78/security-headers-scanner.git
- run: headerscan https://staging.example.com --fail-under B
```

## Development

The tests start a local HTTP server, so they need no internet access.

```bash
ruff check .
pytest -q
```

## License

[MIT](LICENSE)

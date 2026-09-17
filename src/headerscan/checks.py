"""The checks. Each returns findings with a severity and a concrete fix.

Scoring starts at 100 and subtracts per finding: high 20, medium 10, low 5.
Grades: A ≥ 90, B ≥ 80, C ≥ 65, D ≥ 50, otherwise F.
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from email.message import Message

PENALTY = {"high": 20, "medium": 10, "low": 5, "info": 0}


@dataclass
class Finding:
    header: str
    severity: str  # high | medium | low | info
    message: str
    fix: str = ""


@dataclass
class Result:
    url: str
    status: int
    score: int
    grade: str
    findings: list[Finding] = field(default_factory=list)
    present: dict[str, str] = field(default_factory=dict)

    def to_dict(self) -> dict:
        return {
            "url": self.url, "status": self.status, "score": self.score, "grade": self.grade,
            "present": self.present, "findings": [f.__dict__ for f in self.findings],
        }


def _grade(score: int) -> str:
    for limit, g in ((90, "A"), (80, "B"), (65, "C"), (50, "D")):
        if score >= limit:
            return g
    return "F"


def _csp_findings(value: str) -> list[Finding]:
    out = []
    directives = {}
    for part in value.split(";"):
        bits = part.strip().split()
        if bits:
            directives[bits[0].lower()] = [b.lower() for b in bits[1:]]
    scripts = directives.get("script-src", directives.get("default-src"))
    if scripts is None:
        out.append(Finding("Content-Security-Policy", "medium",
                           "CSP has neither script-src nor default-src, so scripts are unrestricted.",
                           "Add default-src 'self' (then widen only what you need)."))
    else:
        if "'unsafe-inline'" in scripts and not any(s.startswith(("'nonce-", "'sha")) for s in scripts):
            out.append(Finding("Content-Security-Policy", "medium",
                               "script-src allows 'unsafe-inline', which defeats most XSS protection.",
                               "Use nonces or hashes for inline scripts instead."))
        if "'unsafe-eval'" in scripts:
            out.append(Finding("Content-Security-Policy", "low", "script-src allows 'unsafe-eval'.",
                               "Remove eval() usage and drop 'unsafe-eval'."))
        if "*" in scripts or "http:" in scripts or "https:" in scripts:
            out.append(Finding("Content-Security-Policy", "medium",
                               "script-src allows scripts from any host.",
                               "List the specific origins you load scripts from."))
    if "frame-ancestors" not in directives:
        out.append(Finding("Content-Security-Policy", "info",
                           "No frame-ancestors directive; X-Frame-Options is relied on for clickjacking.",
                           "Add frame-ancestors 'self' (or 'none')."))
    return out


def _cookie_findings(headers: Message, https: bool) -> list[Finding]:
    out = []
    for raw in headers.get_all("Set-Cookie") or []:
        name = raw.split("=", 1)[0].strip()
        attrs = {a.strip().split("=")[0].lower() for a in raw.split(";")[1:]}
        missing = []
        if https and "secure" not in attrs:
            missing.append("Secure")
        if "httponly" not in attrs:
            missing.append("HttpOnly")
        if "samesite" not in attrs:
            missing.append("SameSite")
        if missing:
            sev = "medium" if re.search(r"sess|auth|token|sid", name, re.I) else "low"
            out.append(Finding("Set-Cookie", sev, f"Cookie '{name}' is missing {', '.join(missing)}.",
                               "Set cookies with Secure; HttpOnly; SameSite=Lax (or Strict)."))
    return out


def evaluate(url: str, status: int, headers: Message) -> Result:
    https = url.lower().startswith("https://")
    get = lambda name: headers.get(name)  # noqa: E731  (case-insensitive lookup)
    findings: list[Finding] = []
    watched = ["Strict-Transport-Security", "Content-Security-Policy", "X-Content-Type-Options",
               "X-Frame-Options", "Referrer-Policy", "Permissions-Policy",
               "Cross-Origin-Opener-Policy", "Server", "X-Powered-By"]
    present = {h: get(h) for h in watched if get(h) is not None}

    if not https:
        findings.append(Finding("(transport)", "high", "The site was served over plain HTTP.",
                                "Serve everything over HTTPS and redirect HTTP to it."))

    hsts = get("Strict-Transport-Security")
    if https:
        if not hsts:
            findings.append(Finding("Strict-Transport-Security", "high", "HSTS is missing.",
                                    "Strict-Transport-Security: max-age=31536000; includeSubDomains"))
        else:
            m = re.search(r"max-age=(\d+)", hsts, re.I)
            if not m or int(m.group(1)) < 15552000:
                findings.append(Finding("Strict-Transport-Security", "low",
                                        "HSTS max-age is below 180 days.",
                                        "Use max-age=31536000 (one year)."))

    csp = get("Content-Security-Policy")
    if not csp:
        sev = "low" if get("Content-Security-Policy-Report-Only") else "medium"
        findings.append(Finding("Content-Security-Policy", sev, "No enforced Content-Security-Policy.",
                                "Start with: default-src 'self'; frame-ancestors 'self'; object-src 'none'"))
    else:
        findings.extend(_csp_findings(csp))

    if (get("X-Content-Type-Options") or "").strip().lower() != "nosniff":
        findings.append(Finding("X-Content-Type-Options", "medium",
                                "X-Content-Type-Options: nosniff is not set.",
                                "X-Content-Type-Options: nosniff"))

    xfo = (get("X-Frame-Options") or "").strip().upper()
    if xfo not in ("DENY", "SAMEORIGIN") and not (csp and "frame-ancestors" in csp.lower()):
        findings.append(Finding("X-Frame-Options", "medium",
                                "The page can be framed by any site (clickjacking).",
                                "X-Frame-Options: DENY, or CSP frame-ancestors 'self'"))

    rp = (get("Referrer-Policy") or "").strip().lower()
    if not rp:
        findings.append(Finding("Referrer-Policy", "low", "Referrer-Policy is not set.",
                                "Referrer-Policy: strict-origin-when-cross-origin"))
    elif rp in ("unsafe-url", "no-referrer-when-downgrade"):
        findings.append(Finding("Referrer-Policy", "low", f"Referrer-Policy '{rp}' leaks full URLs.",
                                "Referrer-Policy: strict-origin-when-cross-origin"))

    if not get("Permissions-Policy"):
        findings.append(Finding("Permissions-Policy", "low", "Permissions-Policy is not set.",
                                "Permissions-Policy: camera=(), microphone=(), geolocation=()"))

    for h in ("Server", "X-Powered-By", "X-AspNet-Version"):
        v = get(h)
        if v and re.search(r"\d", v):
            findings.append(Finding(h, "low", f"{h} reveals a software version ('{v}').",
                                    f"Remove the version from the {h} header."))

    findings.extend(_cookie_findings(headers, https))

    score = max(0, 100 - sum(PENALTY[f.severity] for f in findings))
    order = {"high": 0, "medium": 1, "low": 2, "info": 3}
    findings.sort(key=lambda f: order[f.severity])
    return Result(url, status, score, _grade(score), findings, present)

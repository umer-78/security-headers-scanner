"""headerscan: grade the HTTP security headers of one or more URLs."""

from __future__ import annotations

import argparse
import json
import sys

from .checks import evaluate
from .fetch import FetchError, fetch_headers

COLOR = {"high": "\033[31m", "medium": "\033[33m", "low": "\033[36m", "info": "\033[90m"}
RESET = "\033[0m"


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(prog="headerscan", description=__doc__)
    ap.add_argument("urls", nargs="+", help="e.g. https://example.com")
    ap.add_argument("--json", action="store_true")
    ap.add_argument("--timeout", type=float, default=10.0)
    ap.add_argument("--fail-under", default=None, metavar="GRADE",
                    help="exit 1 if any grade is worse than this (A-F), for CI")
    args = ap.parse_args(argv)
    color = sys.stdout.isatty()

    results, errors = [], 0
    for url in args.urls:
        try:
            final, status, headers = fetch_headers(url, args.timeout)
        except FetchError as exc:
            print(f"error: {exc}", file=sys.stderr)
            errors += 1
            continue
        results.append(evaluate(final, status, headers))

    if args.json:
        print(json.dumps([r.to_dict() for r in results], indent=2))
    else:
        for r in results:
            print(f"{r.url}  (HTTP {r.status})")
            print(f"  Grade {r.grade}  ·  score {r.score}/100")
            for f in r.findings:
                tag = f"{f.severity.upper():6}"
                if color:
                    tag = COLOR[f.severity] + tag + RESET
                print(f"  {tag} {f.header}: {f.message}")
                if f.fix:
                    print(f"         fix → {f.fix}")
            print()

    if errors:
        return 2
    if args.fail_under:
        worst = max("ABCDF".index(r.grade) for r in results) if results else 0
        if worst > "ABCDF".index(args.fail_under.upper()):
            return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

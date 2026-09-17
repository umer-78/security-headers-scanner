"""Fetch response headers with the standard library."""

from __future__ import annotations

import ssl
import urllib.error
import urllib.request
from email.message import Message

USER_AGENT = "headerscan/1.0 (+https://github.com/umer-78/security-headers-scanner)"


class FetchError(Exception):
    pass


def fetch_headers(url: str, timeout: float = 10.0) -> tuple[str, int, Message]:
    """Return (final_url, status, headers). Redirects are followed.

    A 4xx/5xx answer still has headers worth grading, so it is returned, not raised.
    """
    if "://" not in url:
        url = "https://" + url
    if not url.startswith(("http://", "https://")):
        raise FetchError("only http and https URLs are supported")
    req = urllib.request.Request(url, method="GET", headers={"User-Agent": USER_AGENT})
    ctx = ssl.create_default_context()
    try:
        with urllib.request.urlopen(req, timeout=timeout, context=ctx) as resp:
            return resp.geturl(), resp.status, resp.headers
    except urllib.error.HTTPError as err:
        return err.geturl(), err.code, err.headers
    except (urllib.error.URLError, TimeoutError, ssl.SSLError, ValueError) as err:
        raise FetchError(f"could not fetch {url}: {getattr(err, 'reason', err)}") from err

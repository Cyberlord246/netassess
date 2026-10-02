"""Minimal, scope-agnostic HTTP GET used by the endpoint/JS and default-login
analysis stages.

It is deliberately tiny and non-destructive: a single GET, bounded body read,
short timeout, no redirect following, TLS verification disabled (we assess the
server as presented, not validate its chain). Callers MUST scope-authorize the
(ip, port) before calling — this helper performs no scope checks itself.
"""
from __future__ import annotations

import http.client
import ssl
from typing import Optional

_UA = "netassess/analysis (authorized assessment)"


def fetch(ip: str, port: int, scheme: str, path: str = "/", *,
          host_header: Optional[str] = None, timeout: float = 5.0,
          max_bytes: int = 300_000) -> tuple[Optional[int], dict, str]:
    """GET ``scheme://ip:port/path`` and return (status, headers, body_text).

    Returns (None, {}, "") on any connection/read error. Body is capped at
    ``max_bytes`` and decoded leniently.
    """
    conn = None
    try:
        if scheme == "https":
            ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
            ctx.check_hostname = False
            ctx.verify_mode = ssl.CERT_NONE
            conn = http.client.HTTPSConnection(ip, port, timeout=timeout,
                                               context=ctx)
        else:
            conn = http.client.HTTPConnection(ip, port, timeout=timeout)
        headers = {"User-Agent": _UA, "Accept": "*/*", "Connection": "close"}
        if host_header:
            headers["Host"] = host_header
        conn.request("GET", path or "/", headers=headers)
        resp = conn.getresponse()
        raw = resp.read(max_bytes)
        hdrs = {k.lower(): v for k, v in resp.getheaders()}
        text = raw.decode("utf-8", "replace") if raw else ""
        return resp.status, hdrs, text
    except Exception:
        return None, {}, ""
    finally:
        try:
            if conn is not None:
                conn.close()
        except Exception:
            pass

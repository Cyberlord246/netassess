"""httpx adapter — fast bulk HTTP probing when installed.

Shells out to ProjectDiscovery's `httpx` (Go, async) to fingerprint many
``ip:port`` endpoints in one pass — far faster than the built-in per-service
Python probe when there are hundreds/thousands of candidates (a domain list).

Scope safety: we feed httpx bare ``ip:port`` targets (already authorised IPs),
so it connects to those IPs and never resolves a hostname out of scope. Redirect
following is left OFF (httpx default), matching the built-in probe. Virtual-host
/ SNI probing and the OPTIONS/TRACE misconfiguration checks stay in the built-in
path; httpx only provides the bulk status/title/server/tech/tls/cdn fingerprint.

If the binary is missing (or is not ProjectDiscovery's httpx), ``available()`` is
False and the engine uses the built-in probe.
"""
from __future__ import annotations

import json
import re

from ..models import (
    Confidence, HTTPService, Host, Technology, TLSInfo,
)
from .base import ToolAdapter
from .process import ProcResult, run, which

_VER_RE = re.compile(r"v?\d+\.\d+\.\d+")


class HttpxAdapter(ToolAdapter):
    name = "httpx"

    def __init__(self):
        self._checked = False
        self._available = False

    # -- availability (verify it is ProjectDiscovery httpx) --------------- #
    def available(self) -> bool:
        if self._checked:
            return self._available
        self._checked = True
        if which("httpx") is None:
            self._available = False
            return False
        # distinguish PD's httpx from unrelated binaries named "httpx"
        res = run(["httpx", "-version"], timeout=10.0)
        blob = f"{res.stdout}\n{res.stderr}".lower()
        self._available = bool(_VER_RE.search(blob)) and "traceroute" not in blob
        return self._available

    # -- command construction (unit-testable without the binary) --------- #
    def build_argv(self, *, timeout: int = 7, threads: int = 50, rate: float = 0.0,
                   user_agent: str = "netassess/1.0 (authorized security assessment)"
                   ) -> list[str]:
        argv = [
            "httpx",
            "-json",                  # line-delimited JSON
            "-silent",                # no banner/progress on stdout
            "-no-color",
            "-disable-update-check",
            "-status-code",           # ensure fields present regardless of defaults
            "-title",
            "-tech-detect",
            "-web-server",
            "-content-length",
            "-content-type",
            "-location",
            "-cdn",
            "-tls-grab",
            "-timeout", str(max(1, int(timeout))),
            "-threads", str(max(1, threads)),
            "-H", f"User-Agent: {user_agent}",
        ]
        if rate and rate > 0:
            argv += ["-rate-limit", str(int(rate))]
        return argv

    # -- output parsing --------------------------------------------------- #
    def parse_json(self, stdout: str) -> list[dict]:
        out: list[dict] = []
        for line in stdout.splitlines():
            line = line.strip()
            if not line.startswith("{"):
                continue
            try:
                out.append(json.loads(line))
            except json.JSONDecodeError:
                continue
        return out

    # -- run over a set of ip:port targets -------------------------------- #
    def probe(self, targets: list[str], *, timeout: int = 7, threads: int = 50,
              rate: float = 0.0, run_timeout: float = 900.0
              ) -> tuple[list[dict], ProcResult]:
        argv = self.build_argv(timeout=timeout, threads=threads, rate=rate)
        res = run(argv, timeout=run_timeout, input_text="\n".join(targets) + "\n")
        records = self.parse_json(res.stdout) if res.stdout else []
        return records, res

    # -- map one httpx record to an HTTPService --------------------------- #
    def to_http_service(self, rec: dict, ip: str, port: int) -> HTTPService:
        from ..techdetect import response_fingerprint

        def g(*keys, default=""):
            for k in keys:
                if k in rec and rec[k] not in (None, ""):
                    return rec[k]
            return default

        scheme = g("scheme", default="") or (
            "https" if str(g("url")).startswith("https") else "http")
        url = g("url", default=f"{scheme}://{ip}:{port}/")
        status = g("status_code", "status-code", default=None)
        clen = g("content_length", "content-length", default=None)
        techs = g("tech", "technologies", default=[]) or []
        location = g("location", default="")

        svc = HTTPService(
            url=url, ip=ip, port=port, scheme=scheme,
            status=int(status) if isinstance(status, (int, str)) and str(status).isdigit() else None,
            title=str(g("title")),
            server=str(g("webserver", "web_server", "server")),
            content_type=str(g("content_type", "content-type")).split(";", 1)[0],
            content_length=int(clen) if isinstance(clen, (int, str)) and str(clen).isdigit() else None,
            redirect_chain=([f"{status} -> {location}"] if location else []),
        )
        svc.technologies = [
            Technology(name=str(t), category="", evidence="httpx tech-detect",
                       confidence=Confidence.MEDIUM)
            for t in techs if t]
        svc.cdn = str(g("cdn_name", "cdn", default="")) if g("cdn", default=False) else \
            str(g("cdn_name", default=""))
        svc.tls = _tls_from_httpx(rec.get("tls") or rec.get("tls_grab"))
        svc.fingerprint = response_fingerprint(svc)
        return svc


def _tls_from_httpx(t) -> "TLSInfo | None":
    if not isinstance(t, dict):
        return None
    sans = t.get("subject_an") or t.get("subject_alt_names") or t.get("san") or []
    return TLSInfo(
        subject=str(t.get("subject_cn") or t.get("subject_dn") or ""),
        issuer=str(t.get("issuer_cn") or t.get("issuer_dn") or ""),
        sans=[str(s) for s in sans],
        not_before=str(t.get("not_before") or ""),
        not_after=str(t.get("not_after") or ""),
        negotiated_protocol=str(t.get("tls_version") or t.get("version") or ""),
        negotiated_cipher=str(t.get("cipher") or ""),
    )

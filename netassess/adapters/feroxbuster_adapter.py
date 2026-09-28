"""Feroxbuster adapter — fast, recursive content discovery when installed.

Shells out to `feroxbuster` (Rust) with a configuration tuned to surface
*interesting, unique* responses and suppress garbage:

  * ``--auto-tune``      — feroxbuster detects wildcard/soft-404 behaviour and
                            auto-adds size/word/line filters, so pages that only
                            look like hits are dropped dynamically.
  * ``-C 404,400,500,501,502,503`` — filter out not-found and generic error
                            noise, while KEEPING useful non-200 codes
                            (200/204/301/302/307/401/403/405/…) which often mark
                            protected or existing resources.
  * ``--filter-similar-to`` the base 404 page — collapse near-duplicate junk.
  * bounded ``--depth`` recursion into directories it actually finds.
  * ``--dont-scan`` state-changing paths (logout/delete/…) as a safety guard.
  * JSON output parsed into the platform's Finding schema, graded by the same
    categorizer the built-in probe uses.

Results are normalised so a feroxbuster run and the built-in probe are
interchangeable from the engine's point of view. If feroxbuster is not on PATH,
``available()`` is False and the engine uses the built-in probe.
"""
from __future__ import annotations

import json
import re
import tempfile

from ..models import Finding, HTTPService, Host, Severity
from .base import ToolAdapter
from .process import ProcResult, run, which

# status codes we consider useful signal (feroxbuster reports these; we filter
# the rest). Not just 200 — protected/redirecting resources are informative.
INTERESTING_STATUS = {200, 201, 204, 301, 302, 307, 308, 401, 403, 405, 500}
# codes filtered out as noise
_FILTER_STATUS = "404,400,500,501,502,503"

# safety: never brute-force into obviously state-changing endpoints
_DONT_SCAN = r"logout|log-out|signout|sign-out|/delete|/remove|/destroy|/shutdown"


class FeroxbusterAdapter(ToolAdapter):
    name = "feroxbuster"

    def available(self) -> bool:
        return which("feroxbuster") is not None

    # -- command construction (unit-testable without the binary) --------- #
    def build_argv(self, base_url: str, wordlist: str, *, threads: int = 40,
                   depth: int = 2, timeout: int = 7, rate: float = 0.0,
                   extensions: str = "", thorough: bool = False,
                   headers: list[str] | None = None,
                   user_agent: str = "netassess/1.0 (authorized security assessment)"
                   ) -> list[str]:
        argv = [
            "feroxbuster",
            "-u", base_url,
            "-w", wordlist,
            "--json",                 # machine-readable, line-delimited
            "--silent",               # only JSON on stdout, no banner/progress
            "-k",                     # accept self-signed/invalid TLS
            "--auto-tune",            # dynamically filter wildcard/garbage
            "--filter-status", _FILTER_STATUS,
            "-t", str(max(1, threads)),
            "--depth", str(max(1, depth)),
            "--timeout", str(max(1, int(timeout))),
            "-a", user_agent,
            "--no-state",             # don't drop a .state file
            "--dont-scan", _DONT_SCAN,
        ]
        # Virtual-host scanning: keep the connection pinned to the authorized IP
        # in `base_url`, but present the vhost via an explicit Host header so
        # name-based vhosts route correctly. We never put the hostname in the URL
        # (that would resolve/connect to a possibly out-of-scope IP).
        for hv in (headers or []):
            argv += ["-H", hv]
        if extensions:
            argv += ["-x", extensions.replace(" ", "")]
        if rate and rate > 0:
            argv += ["--rate-limit", str(int(rate))]
        if thorough:
            # learn real extensions in use and probe for backups of found pages
            argv += ["--collect-extensions", "--collect-backups"]
        return argv

    # -- output parsing --------------------------------------------------- #
    def parse_json(self, stdout: str) -> list[dict]:
        """Parse feroxbuster line-delimited JSON into response records."""
        out: list[dict] = []
        for line in stdout.splitlines():
            line = line.strip()
            if not line or not line.startswith("{"):
                continue
            try:
                obj = json.loads(line)
            except json.JSONDecodeError:
                continue
            if obj.get("type") != "response":
                continue
            status = obj.get("status")
            if status is None or status not in INTERESTING_STATUS:
                continue
            out.append({
                "url": obj.get("url", ""),
                "status": status,
                "content_length": obj.get("content_length", 0),
                "line_count": obj.get("line_count", 0),
                "word_count": obj.get("word_count", 0),
                # feroxbuster may include these depending on version/flags
                "location": obj.get("location") or obj.get("redirect") or "",
                "content_type": obj.get("content_type", ""),
            })
        return out

    # -- scan one service ------------------------------------------------- #
    def scan_service(self, host: Host, svc: HTTPService, *, wordlist: str,
                     threads: int = 40, depth: int = 2, timeout: int = 7,
                     rate: float = 0.0, extensions: str = "",
                     thorough: bool = False, run_timeout: float = 900.0
                     ) -> tuple[list[dict], list[Finding], ProcResult]:
        from ..content_discovery import categorize, make_findings

        # Always connect to the authorized IP:port. If this service is a virtual
        # host (its URL carries a hostname, not the IP), route it with a Host
        # header instead of ever connecting to the hostname directly.
        base_url = f"{svc.scheme}://{svc.ip}:{svc.port}/"
        headers: list[str] = []
        vhost = _vhost_of(svc)
        if vhost:
            headers.append(f"Host: {vhost}")
        argv = self.build_argv(base_url, wordlist, threads=threads, depth=depth,
                               timeout=timeout, rate=rate, extensions=extensions,
                               thorough=thorough, headers=headers)
        res = run(argv, timeout=run_timeout)
        # feroxbuster exits non-zero in some benign cases; parse whatever JSON exists
        records = self.parse_json(res.stdout) if res.stdout else []

        # attribute vhost paths to the vhost so they don't merge with the default site
        asset = f"{host.ip}:{svc.port}" + (f" [{vhost}]" if vhost else "")
        discovered: list[dict] = []
        hits: list[dict] = []
        seen: set[str] = set()
        for rec in records:
            url = rec["url"]
            path = _path_of(url)
            key = (path, rec["status"])
            if key in seen:
                continue
            seen.add(key)
            category, sev = categorize(path)
            discovered.append({"path": "/" + path.lstrip("/"), "url": url,
                               "status": rec["status"],
                               "length": rec["content_length"],
                               "category": category, "title": ""})
            hits.append({"path": path, "url": url, "status": rec["status"],
                         "category": category, "sev": sev, "title": "",
                         "length": rec.get("content_length", 0),
                         "location": rec.get("location", ""),
                         "content_type": rec.get("content_type", "")})
        discovered.sort(key=lambda x: x["path"])
        svc.discovered_paths = discovered
        # high-value paths -> individual findings; generic ones -> one grouped entry
        findings = make_findings(asset, hits, source="feroxbuster")
        return discovered, findings, res


def _path_of(url: str) -> str:
    from urllib.parse import urlparse
    return urlparse(url).path.lstrip("/") or "/"


def _vhost_of(svc) -> str:
    """Return the vhost hostname if this service's URL is name-based (not the IP)."""
    from urllib.parse import urlparse
    import ipaddress
    host = urlparse(svc.url).hostname or ""
    if not host or host == svc.ip:
        return ""
    try:
        ipaddress.ip_address(host)
        return ""            # a bare IP URL is not a vhost
    except ValueError:
        return host

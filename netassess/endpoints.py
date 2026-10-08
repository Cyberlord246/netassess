"""Endpoint / JS analysis.

For each discovered HTTP service, fetch the root document (scope-gated, one GET)
and extract meaningful endpoints: linked paths, referenced JavaScript files, and
API-looking URLs embedded in markup/inline script. The result is attached to the
service (``svc.endpoints``) and summarised as an informational finding, with
sensitive-looking paths highlighted.

Non-destructive: GET only, bounded body, no crawling of off-target hosts.
"""
from __future__ import annotations

import re
from urllib.parse import urljoin, urlparse

from .models import Confidence, Finding, Severity, ValidationState
from .webfetch import fetch

# attribute links and script/style/img sources
_ATTR = re.compile(r"""(?:href|src|action)\s*=\s*["']([^"'>\s]+)["']""", re.I)
# URLs/paths in inline JS: fetch("..."), axios.get('...'), "/api/...", url: "..."
_JS_URL = re.compile(r"""["'`](/[A-Za-z0-9_\-./]{1,200}|https?://[^"'`\s]{1,200})["'`]""")
# obvious API/graphql/websocket hints
_API_HINT = re.compile(r"""["'`]((?:/|https?://)[^"'`\s]*(?:api|graphql|v\d|rest|rpc|ws)[^"'`\s]*)["'`]""", re.I)

_SENSITIVE = ("admin", "login", "api", "graphql", "config", "backup", ".env",
              "token", "secret", "debug", "actuator", "swagger", "/.git",
              "upload", "console", "dashboard", "internal")

_MAX_ENDPOINTS = 200


class EndpointAnalyzer:
    def __init__(self, config, scope):
        self.config = config
        self.scope = scope
        self.timeout = float(getattr(config, "timeout", 5.0)) + 2.0

    def analyze_service(self, host, svc) -> list[str]:
        """Return the list of endpoints extracted for one service (also stored on
        ``svc.endpoints``)."""
        if not self.scope.authorize(svc.ip, svc.port).allowed:
            return []
        host_header = None
        # if the service URL carries a vhost name, present it (keeps SNI/Host right)
        parsed = urlparse(svc.url)
        if parsed.hostname and parsed.hostname != svc.ip:
            host_header = parsed.hostname
        status, headers, body = fetch(svc.ip, svc.port, svc.scheme, "/",
                                      host_header=host_header, timeout=self.timeout)
        if not body:
            return []
        eps = self._extract(body, svc, parsed)
        svc.endpoints = eps
        # keep the root body around so a caller can scan it for secrets too
        self._last_root = (body, f"{svc.scheme}://{parsed.hostname or svc.ip}:{svc.port}/")
        self._favicon(host, svc, host_header)
        return eps

    def _favicon(self, host, svc, host_header) -> None:
        """Fetch /favicon.ico (if any) and store the Shodan-style hash; add a
        Technology when the hash is a known product."""
        from .favicon import favicon_hash, identify
        raw = self._raw_get(svc, host_header, "/favicon.ico")  # binary-safe GET
        if not raw:
            return
        try:
            h = favicon_hash(raw)
        except Exception:
            return
        svc.favicon_hash = str(h)
        prod = identify(h)
        if prod:
            from .models import Confidence, Technology
            svc.technologies.append(Technology(
                name=prod, category="app", confidence=Confidence.HIGH,
                evidence=f"favicon hash {h}"))

    def _raw_get(self, svc, host_header, path) -> bytes:
        import http.client
        import ssl
        conn = None
        try:
            if svc.scheme == "https":
                ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
                ctx.check_hostname = False
                ctx.verify_mode = ssl.CERT_NONE
                conn = http.client.HTTPSConnection(svc.ip, svc.port,
                                                   timeout=self.timeout, context=ctx)
            else:
                conn = http.client.HTTPConnection(svc.ip, svc.port,
                                                  timeout=self.timeout)
            headers = {"User-Agent": "netassess", "Connection": "close"}
            if host_header:
                headers["Host"] = host_header
            conn.request("GET", path, headers=headers)
            r = conn.getresponse()
            if r.status != 200:
                return b""
            return r.read(200_000)
        except Exception:
            return b""
        finally:
            try:
                if conn:
                    conn.close()
            except Exception:
                pass

    def scan_js_secrets(self, host, svc, *, max_files: int = 20,
                        max_bytes: int = 1_000_000) -> list:
        """Fetch the service's referenced JS files (and reuse the root body) and
        scan them for leaked secrets. Bounded + scope-gated; returns Findings."""
        from .secrets import scan_text, findings_for
        if not self.scope.authorize(svc.ip, svc.port).allowed:
            return []
        parsed = urlparse(svc.url)
        host_header = parsed.hostname if (parsed.hostname and
                                          parsed.hostname != svc.ip) else None
        base = f"{svc.scheme}://{parsed.hostname or svc.ip}:{svc.port}"

        hits: list[dict] = []
        # 1) the root document we already fetched (inline script / config blobs)
        root = getattr(self, "_last_root", None)
        if root and root[1].startswith(base):
            hits += scan_text(root[0], root[1])

        # 2) the referenced .js files (bounded)
        js_paths = [e for e in (svc.endpoints or [])
                    if e.split("?", 1)[0].lower().endswith(".js")][:max_files]
        for path in js_paths:
            st, _h, body = fetch(svc.ip, svc.port, svc.scheme,
                                 path if path.startswith("/") else "/" + path,
                                 host_header=host_header, timeout=self.timeout,
                                 max_bytes=max_bytes)
            if body:
                hits += scan_text(body, f"{base}{path if path.startswith('/') else '/' + path}")
        return findings_for(f"{svc.ip}:{svc.port}", hits)

    def _extract(self, body: str, svc, parsed) -> list[str]:
        base = f"{svc.scheme}://{parsed.hostname or svc.ip}:{svc.port}/"
        found: list[str] = []
        seen: set[str] = set()

        def add(raw: str):
            raw = raw.strip()
            if not raw or raw.startswith(("data:", "mailto:", "javascript:", "#",
                                          "tel:")):
                return
            # normalise to an absolute URL, then keep only same-host references
            absu = urljoin(base, raw)
            p = urlparse(absu)
            if p.scheme not in ("http", "https"):
                return
            if p.hostname not in (svc.ip, parsed.hostname):
                return                       # off-target: do not record/crawl
            key = p.path + (("?" + p.query) if p.query else "")
            if not key or key in seen:
                return
            seen.add(key)
            found.append(key)

        for rx in (_ATTR, _API_HINT, _JS_URL):
            for m in rx.findall(body):
                add(m)
                if len(found) >= _MAX_ENDPOINTS:
                    return found
        return found

    def finding_for(self, svc, eps: list[str]) -> Finding | None:
        if not eps:
            return None
        js = [e for e in eps if e.split("?")[0].endswith(".js")]
        sensitive = sorted({e for e in eps
                            if any(s in e.lower() for s in _SENSITIVE)})
        sev = Severity.LOW if sensitive else Severity.INFO
        sample = ", ".join(eps[:15]) + (" …" if len(eps) > 15 else "")
        ev = f"{len(eps)} endpoint(s) extracted from {svc.url}"
        if js:
            ev += f"; {len(js)} JS file(s)"
        if sensitive:
            ev += f"; sensitive-looking: {', '.join(sensitive[:10])}"
        ev += f". Sample: {sample}"
        return Finding(
            title="Endpoints / JS references discovered",
            asset=f"{svc.ip}:{svc.port}",
            evidence=ev[:1800],
            description="Links, script references and API-looking paths parsed "
                        "from the service's root document. Useful attack-surface "
                        "leads for further testing.",
            why_it_matters="Reveals application routes, JS bundles and API "
                           "endpoints that expand the testable surface; "
                           "sensitive-looking paths warrant review.",
            severity=sev, confidence=Confidence.MEDIUM,
            impact="Exposed endpoints may reach admin, API or config surfaces.",
            remediation="Review listed endpoints; ensure sensitive routes require "
                        "authentication and are not unintentionally exposed.",
            validation=ValidationState.OBSERVED,
            source="endpoint-analysis", category="endpoint-discovery",
        )

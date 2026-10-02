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
        return eps

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

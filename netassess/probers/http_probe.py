"""HTTP/HTTPS probe — safe metadata collection + technology hints.

Sends a single GET to the root path with a short redirect chain follow. Reads
status, title, headers, server, security headers, and passes the response to the
technology detector. Non-destructive: GET only, no fuzzing, no path brute force,
bounded body read.
"""
from __future__ import annotations

import http.client
import re
import socket
import ssl
import time
from urllib.parse import urlparse

from ..models import (
    Confidence, Finding, Host, HTTPService, Port, Severity, TLSInfo,
    ValidationState,
)
from ..services import default_scheme, is_http
from .base import ProbeResult, ServiceProbe

_TITLE_RE = re.compile(r"<title[^>]*>(.*?)</title>", re.I | re.S)
_MAX_BODY = 65536
_MAX_REDIRECTS = 4

# Security headers we check for presence.
SECURITY_HEADERS = [
    "strict-transport-security",
    "content-security-policy",
    "x-frame-options",
    "x-content-type-options",
    "referrer-policy",
    "permissions-policy",
]

# Headers that leak infrastructure/version info.
_DISCLOSURE_HEADERS = ["server", "x-powered-by", "x-aspnet-version",
                       "x-aspnetmvc-version", "x-generator"]


class HTTPProbe(ServiceProbe):
    name = "http"

    def matches(self, port: Port) -> bool:
        # Known web ports, or any open port that no other prober identified —
        # unlabeled services are very often HTTP on non-standard ports. The GET
        # probe fails gracefully if the port does not speak HTTP.
        return is_http(port) or port.service.name in ("", "unknown")

    def probe(self, host: Host, port: Port) -> ProbeResult:
        ip, num = host.ip, port.number
        if not self.in_scope(ip, num):
            return ProbeResult(error="scope denied")

        scheme = default_scheme(port)
        svc, err = self._fetch(host, ip, num, scheme)
        if svc is None:
            # try the other scheme once (e.g. 8080 that is actually https)
            other = "http" if scheme == "https" else "https"
            svc, err2 = self._fetch(host, ip, num, other)
            if svc is None:
                return ProbeResult(error=err or err2)

        from ..techdetect import detect_technologies
        svc.technologies = detect_technologies(svc)

        findings = self._evaluate(host, port, svc)
        host.http_services.append(svc)
        return ProbeResult(data={"http": svc.to_dict()}, findings=findings)

    # -- fetch ------------------------------------------------------------ #
    def _fetch(self, host: Host, ip: str, port: int, scheme: str
               ) -> tuple[HTTPService | None, str]:
        url = f"{scheme}://{ip}:{port}/"
        chain: list[str] = []
        current_scheme, current_host, current_port, path = scheme, ip, port, "/"
        server_name = host.hostnames[0] if host.hostnames else None

        for _ in range(_MAX_REDIRECTS + 1):
            if not self.in_scope(current_host if _is_ip(current_host) else ip, current_port):
                break
            resp = self._one_request(ip, current_scheme, current_port, current_host,
                                     path, server_name)
            if resp is None:
                if not chain:
                    return None, "connection failed"
                break
            status, headers, body, elapsed, tls = resp
            location = headers.get("location")
            if status in (301, 302, 303, 307, 308) and location and len(chain) < _MAX_REDIRECTS:
                chain.append(f"{status} -> {location}")
                nxt = urlparse(location)
                if nxt.scheme and nxt.hostname:
                    # Only follow redirects that stay on the same IP/host we target.
                    if nxt.hostname not in (ip, current_host) and nxt.hostname != server_name:
                        # off-target redirect: record but do not follow (scope safety)
                        chain[-1] += " (not followed: off-target)"
                        return self._build(url, ip, port, scheme, status, headers,
                                           body, elapsed, tls, chain), ""
                    current_scheme = nxt.scheme
                    current_port = nxt.port or (443 if nxt.scheme == "https" else 80)
                    path = nxt.path or "/"
                else:
                    path = location if location.startswith("/") else "/" + location
                continue
            return self._build(url, ip, port, scheme, status, headers, body,
                               elapsed, tls, chain), ""
        return None, "no response"

    def _one_request(self, ip, scheme, port, host_header, path, server_name):
        start = time.monotonic()
        with self.scope.slot(ip, port) as s:
            if not s.allowed:
                return None
            try:
                if scheme == "https":
                    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
                    ctx.check_hostname = False
                    ctx.verify_mode = ssl.CERT_OPTIONAL
                    try:
                        ctx.load_default_certs()
                    except OSError:
                        pass
                    conn = http.client.HTTPSConnection(
                        ip, port, timeout=self.config.timeout, context=ctx)
                else:
                    conn = http.client.HTTPConnection(
                        ip, port, timeout=self.config.timeout)
                headers = {
                    "Host": server_name or ip,
                    "User-Agent": "netassess/1.0 (authorized security assessment)",
                    "Accept": "*/*",
                    "Connection": "close",
                }
                conn.request("GET", path or "/", headers=headers)
                resp = conn.getresponse()
                raw = resp.read(_MAX_BODY)
                elapsed = (time.monotonic() - start) * 1000.0
                hdrs = {k.lower(): v for k, v in resp.getheaders()}
                tls_info = None
                if scheme == "https":
                    tls_info = self._tls_from_conn(conn)
                conn.close()
                return resp.status, hdrs, raw, elapsed, tls_info
            except (http.client.HTTPException, ssl.SSLError, socket.timeout,
                    OSError) as exc:
                return None

    def _tls_from_conn(self, conn) -> TLSInfo | None:
        try:
            sock = conn.sock
            cert = sock.getpeercert() or {}
            info = TLSInfo(
                negotiated_protocol=sock.version() or "",
                negotiated_cipher=(sock.cipher() or ("", "", 0))[0],
            )
            if cert:
                subj = ", ".join(f"{k}={v}" for rdn in cert.get("subject", ())
                                 for k, v in rdn)
                iss = ", ".join(f"{k}={v}" for rdn in cert.get("issuer", ())
                                for k, v in rdn)
                info.subject = subj
                info.issuer = iss
                info.sans = [v for (t, v) in cert.get("subjectAltName", ()) if t == "DNS"]
                info.not_after = cert.get("notBefore", "")
                info.not_after = cert.get("notAfter", "")
            return info
        except (AttributeError, OSError):
            return None

    def _build(self, url, ip, port, scheme, status, headers, body, elapsed,
               tls, chain) -> HTTPService:
        text = body.decode("utf-8", errors="replace")
        title = ""
        m = _TITLE_RE.search(text)
        if m:
            title = re.sub(r"\s+", " ", m.group(1)).strip()[:200]
        sec = {h: (h in headers) for h in SECURITY_HEADERS}
        clen = headers.get("content-length")
        return HTTPService(
            url=url, ip=ip, port=port, scheme=scheme, status=status,
            title=title, server=headers.get("server", ""),
            content_type=headers.get("content-type", ""),
            content_length=int(clen) if clen and clen.isdigit() else len(body),
            redirect_chain=chain, headers=dict(headers), security_headers=sec,
            tls=tls, response_ms=round(elapsed, 2),
        )

    # -- findings --------------------------------------------------------- #
    def _evaluate(self, host: Host, port: Port, svc: HTTPService) -> list[Finding]:
        asset = f"{host.ip}:{port.number}"
        out: list[Finding] = []

        missing = [h for h, present in svc.security_headers.items() if not present]
        # HSTS only relevant on https
        if svc.scheme != "https" and "strict-transport-security" in missing:
            missing.remove("strict-transport-security")
        if missing:
            out.append(Finding(
                title="Missing HTTP security headers", asset=asset,
                evidence="absent: " + ", ".join(missing),
                description="One or more recommended security response headers are absent.",
                why_it_matters="Missing headers weaken defenses against clickjacking, MIME sniffing, and protocol downgrade.",
                severity=Severity.LOW, confidence=Confidence.HIGH,
                impact="Increased client-side attack surface (XSS, clickjacking, downgrade).",
                remediation="Add CSP, X-Frame-Options, X-Content-Type-Options, HSTS (https), Referrer-Policy.",
                validation=ValidationState.CONFIRMED, source="http-probe", category="http-config",
            ))

        disclosed = {h: svc.headers[h] for h in _DISCLOSURE_HEADERS
                     if h in svc.headers and svc.headers[h]}
        if disclosed:
            detail = "; ".join(f"{k}: {v}" for k, v in disclosed.items())
            out.append(Finding(
                title="Software version disclosure via HTTP headers", asset=asset,
                evidence=detail,
                description="HTTP response headers reveal server/framework products and versions.",
                why_it_matters="Version banners let attackers match known CVEs to the exact build.",
                severity=Severity.INFO, confidence=Confidence.HIGH,
                remediation="Suppress or genericise Server/X-Powered-By headers.",
                validation=ValidationState.CONFIRMED, source="http-probe", category="info-disclosure",
            ))

        # Admin/management interface exposure heuristic.
        title_l = (svc.title or "").lower()
        admin_words = ("login", "sign in", "admin", "dashboard", "console",
                       "phpmyadmin", "kibana", "grafana", "jenkins", "management")
        if any(w in title_l for w in admin_words):
            out.append(Finding(
                title="Possible administrative/login interface exposed", asset=asset,
                evidence=f"page title: {svc.title!r}",
                description="The root page appears to be a management or authentication interface.",
                why_it_matters="Publicly reachable admin panels are prime targets for credential attacks.",
                severity=Severity.MEDIUM, confidence=Confidence.LOW,
                impact="If reachable from untrusted networks, expands authentication attack surface.",
                remediation="Restrict admin interfaces to trusted networks/VPN; enforce MFA.",
                validation=ValidationState.NEEDS_VALIDATION, source="http-probe", category="exposure",
            ))
        return out


def _is_ip(value: str) -> bool:
    import ipaddress
    try:
        ipaddress.ip_address(value)
        return True
    except ValueError:
        return False

"""Virtual-host probing from TLS certificate SANs (in-scope, read-only).

One IP often serves many web apps, each answering only to the right ``Host``
header. During TLS probing we already collect each certificate's Subject
Alternative Names (SANs) and CN — hostnames the server itself claims. This module
re-requests the *same in-scope IP:port* using those hostnames as the ``Host``
header and reports any that yield a **different** application than the default
(IP) response.

Scope safety: it never scans a new IP. Every request targets an IP:port already
authorized and already found open; it only varies the Host header, and is
scope-gated + rate-limited like everything else. GET only, no writes.
"""
from __future__ import annotations

import http.client
import re
import socket
import ssl

from .config import Config
from .models import (
    Confidence, Finding, HTTPService, Host, Severity, ValidationState,
)
from .scope import ScopeEngine

_TITLE_RE = re.compile(r"<title[^>]*>(.*?)</title>", re.I | re.S)
_CN_RE = re.compile(r"(?:commonName|CN)=([^,]+)", re.I)
_MAX_BODY = 32768


def _is_ip(v: str) -> bool:
    import ipaddress
    try:
        ipaddress.ip_address(v)
        return True
    except ValueError:
        return False


class VhostProber:
    def __init__(self, config: Config, scope: ScopeEngine):
        self.config = config
        self.scope = scope

    # -- candidate hostnames from certs already collected ----------------- #
    def _candidates(self, host: Host, svc: HTTPService) -> list[str]:
        names: list[str] = []
        tlsinfos = []
        if svc.tls:
            tlsinfos.append(svc.tls)
        if svc.port in host.tls:
            tlsinfos.append(host.tls[svc.port])
        for tls in tlsinfos:
            names.extend(tls.sans or [])
            m = _CN_RE.search(tls.subject or "")
            if m:
                names.append(m.group(1).strip())
        already = {host.hostnames[0].lower() if host.hostnames else "", host.ip}
        out, seen = [], set()
        for n in names:
            n = n.strip().lower().rstrip(".")
            if not n or n in seen or n in already:
                continue
            if n.startswith("*.") or _is_ip(n):   # skip wildcards / bare IPs
                seen.add(n)
                continue
            seen.add(n)
            out.append(n)
        return out

    # -- GET with explicit SNI + Host header ------------------------------ #
    def _get(self, ip: str, port: int, scheme: str, host_header: str, sni=None):
        """Connect to the authorized IP, but set the TLS SNI (server_hostname) and
        the HTTP Host header to `sni`/`host_header`. This exercises BOTH SNI-based
        and name-based virtual hosting. Connecting by IP means we never resolve or
        leave the authorized target. `sni=None` sends no SNI (default backend)."""
        with self.scope.slot(ip, port) as s:
            if not s.allowed:
                return None
            sock = None
            try:
                sock = socket.create_connection((ip, port), timeout=self.config.timeout)
                if scheme == "https":
                    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
                    ctx.check_hostname = False
                    ctx.verify_mode = ssl.CERT_NONE
                    # SNI = sni (a hostname) or None (no SNI) — never the IP
                    sock = ctx.wrap_socket(sock, server_hostname=(sni or None))
                sock.settimeout(self.config.timeout)
                req = (f"GET / HTTP/1.1\r\nHost: {host_header}\r\n"
                       f"User-Agent: netassess/1.0 (authorized security assessment)\r\n"
                       f"Accept: */*\r\nConnection: close\r\n\r\n")
                sock.sendall(req.encode("latin-1"))
                data = b""
                while len(data) < _MAX_BODY:
                    chunk = sock.recv(4096)
                    if not chunk:
                        break
                    data += chunk
                return self._parse_http(data)
            except (ssl.SSLError, socket.timeout, OSError):
                return None
            finally:
                if sock is not None:
                    try:
                        sock.close()
                    except OSError:
                        pass

    @staticmethod
    def _parse_http(data: bytes):
        if not data:
            return None
        head, _, body = data.partition(b"\r\n\r\n")
        lines = head.split(b"\r\n")
        try:
            status = int(lines[0].split()[1])
        except (IndexError, ValueError):
            return None
        loc = ""
        for ln in lines[1:]:
            if ln.lower().startswith(b"location:"):
                loc = ln.split(b":", 1)[1].strip().decode("latin-1", "replace")
                break
        title = ""
        m = _TITLE_RE.search(body.decode("utf-8", "replace"))
        if m:
            title = re.sub(r"\s+", " ", m.group(1)).strip()[:120]
        return {"status": status, "len": len(body), "title": title, "loc": loc}

    def _differs(self, base, r) -> bool:
        if r is None:
            return False
        if base is None:
            return r["status"] < 500
        if r["status"] != base["status"]:
            return True
        if r["title"] != base["title"] and (r["title"] or base["title"]):
            return True
        if r["loc"] != base["loc"]:
            return True
        # sizable body-length difference (ignore tiny variance)
        diff = abs(r["len"] - base["len"])
        return diff > max(96, base["len"] * 0.10)

    # -- probe one HTTP service ------------------------------------------- #
    def probe_service(self, host: Host, svc: HTTPService) -> list[Finding]:
        ip, port, scheme = svc.ip, svc.port, svc.scheme
        if not self.scope.authorize(ip, port).allowed:
            return []
        candidates = self._candidates(host, svc)
        if not candidates:
            return []
        # baseline = default backend (Host=IP, no SNI)
        base = self._get(ip, port, scheme, ip, sni=None)
        findings: list[Finding] = []
        for name in candidates:
            # set BOTH the TLS SNI and the HTTP Host header to the candidate
            r = self._get(ip, port, scheme, name, sni=name)
            if not self._differs(base, r):
                continue
            url = f"{scheme}://{name}:{port}/"
            host.http_services.append(HTTPService(
                url=url, ip=ip, port=port, scheme=scheme, status=r["status"],
                title=r["title"], content_length=r["len"],
            ))
            findings.append(Finding(
                title=f"Virtual host serves a distinct application: {name}",
                asset=f"{ip}:{port}",
                evidence=f"SNI+Host: {name} -> HTTP {r['status']}"
                         + (f", title={r['title']!r}" if r["title"] else "")
                         + " (differs from default response)",
                description=f"The certificate SAN/CN '{name}' resolves to a "
                            f"different web application on {ip}:{port} than the "
                            "default (IP) response.",
                why_it_matters="Name-based virtual hosts expose additional apps on "
                               "the same IP that an IP-only scan would miss — each "
                               "is its own attack surface.",
                severity=Severity.LOW, confidence=Confidence.HIGH,
                impact="Additional reachable web application / attack surface.",
                remediation="Confirm the vhost is intended to be exposed; assess it "
                            "as a distinct application.",
                validation=ValidationState.OBSERVED, source="vhost-probe",
                category="vhost-discovery",
            ))
        return findings

"""TLS probe — safe certificate & configuration metadata collection.

Non-destructive: performs standard TLS handshakes to read the certificate,
negotiated protocol/cipher, and (best-effort) which protocol versions the
service will accept. No cipher-flooding, no downgrade attacks, no fuzzing.
"""
from __future__ import annotations

import socket
import ssl
import time
from datetime import datetime, timezone

from ..models import (
    Confidence, Finding, Host, Port, Severity, TLSInfo, ValidationState,
)
from ..services import is_tls
from .base import ProbeResult, ServiceProbe


_PROTO_ATTEMPTS = [
    ("TLSv1.3", getattr(ssl, "TLSVersion", None) and ssl.TLSVersion.TLSv1_3),
    ("TLSv1.2", getattr(ssl, "TLSVersion", None) and ssl.TLSVersion.TLSv1_2),
    ("TLSv1.1", getattr(ssl, "TLSVersion", None) and ssl.TLSVersion.TLSv1_1),
    ("TLSv1.0", getattr(ssl, "TLSVersion", None) and ssl.TLSVersion.TLSv1),
]

# Protocols considered weak/deprecated if the server accepts them.
_WEAK_PROTOCOLS = {"TLSv1.0", "TLSv1.1", "SSLv3", "SSLv2"}


def _parse_cert_time(value: str) -> datetime | None:
    try:
        return datetime.strptime(value, "%b %d %H:%M:%S %Y %Z").replace(
            tzinfo=timezone.utc)
    except (ValueError, TypeError):
        return None


class TLSProbe(ServiceProbe):
    name = "tls"

    def matches(self, port: Port) -> bool:
        return is_tls(port)

    def probe(self, host: Host, port: Port) -> ProbeResult:
        ip, num = host.ip, port.number
        if not self.in_scope(ip, num):
            return ProbeResult(error="scope denied")

        server_name = host.hostnames[0] if host.hostnames else None
        info = TLSInfo()

        cert, neg_proto, neg_cipher, err = self._handshake(ip, num, server_name)
        if err and not cert:
            return ProbeResult(error=err)
        info.negotiated_protocol = neg_proto
        info.negotiated_cipher = neg_cipher

        if cert:
            self._fill_cert(info, cert, server_name)

        info.protocols_offered = self._enumerate_protocols(ip, num, server_name)

        findings = self._evaluate(host, port, info)
        host.tls[num] = info
        return ProbeResult(data={"tls": info.to_dict()}, findings=findings)

    # -- handshake helpers ------------------------------------------------ #
    def _handshake(self, ip: str, port: int, server_name):
        # CERT_OPTIONAL returns the PARSED certificate dict even when the chain
        # does not verify, without raising — exactly what we want for read-only
        # metadata collection against untrusted/self-signed endpoints.
        ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_OPTIONAL
        try:
            ctx.load_default_certs()
        except OSError:
            pass
        with self.scope.slot(ip, port) as s:
            if not s.allowed:
                return None, "", "", "scope denied"
            try:
                raw = socket.create_connection((ip, port), timeout=self.config.timeout)
                with ctx.wrap_socket(raw, server_hostname=server_name or ip) as ss:
                    cert = ss.getpeercert() or {}
                    return cert, ss.version() or "", (ss.cipher() or ("", "", 0))[0], ""
            except (ssl.SSLError, socket.timeout, OSError) as exc:
                return None, "", "", str(exc)

    def _fill_cert(self, info: TLSInfo, cert: dict, server_name):
        def _join(field):
            parts = []
            for rdn in cert.get(field, ()):
                for k, v in rdn:
                    parts.append(f"{k}={v}")
            return ", ".join(parts)

        info.subject = _join("subject")
        info.issuer = _join("issuer")
        info.sans = [v for (t, v) in cert.get("subjectAltName", ()) if t == "DNS"]
        info.not_before = cert.get("notBefore", "")
        info.not_after = cert.get("notAfter", "")

        na = _parse_cert_time(info.not_after)
        nb = _parse_cert_time(info.not_before)
        now = datetime.now(timezone.utc)
        if na:
            info.days_to_expiry = (na - now).days
            info.expired = na < now
        if nb and na:
            info.self_signed = info.subject == info.issuer and info.subject != ""

        # hostname match (only meaningful if we know the intended name)
        if server_name:
            names = set(info.sans)
            info.hostname_match = server_name in names or any(
                _wildcard_match(server_name, n) for n in names)

    def _enumerate_protocols(self, ip: str, port: int, server_name) -> list[str]:
        offered = []
        for label, ver in _PROTO_ATTEMPTS:
            if not ver:
                continue
            ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
            ctx.check_hostname = False
            ctx.verify_mode = ssl.CERT_NONE
            try:
                ctx.minimum_version = ver
                ctx.maximum_version = ver
            except (ValueError, OSError):
                continue
            with self.scope.slot(ip, port) as s:
                if not s.allowed:
                    break
                try:
                    raw = socket.create_connection((ip, port), timeout=self.config.timeout)
                    with ctx.wrap_socket(raw, server_hostname=server_name or ip) as ss:
                        offered.append(label)
                except (ssl.SSLError, OSError):
                    pass
        return offered

    # -- findings --------------------------------------------------------- #
    def _evaluate(self, host: Host, port: Port, info: TLSInfo) -> list[Finding]:
        asset = f"{host.ip}:{port.number}"
        findings: list[Finding] = []

        if info.expired:
            info.problems.append("certificate expired")
            findings.append(Finding(
                title="Expired TLS certificate", asset=asset,
                evidence=f"notAfter={info.not_after}",
                description="The server's TLS certificate has expired.",
                why_it_matters="Clients will show trust errors; may indicate unmaintained service.",
                severity=Severity.MEDIUM, confidence=Confidence.HIGH,
                impact="Loss of trust; potential MITM if users click through warnings.",
                remediation="Renew and deploy a valid certificate; automate renewal.",
                validation=ValidationState.CONFIRMED, source="tls-probe", category="tls",
            ))
        elif info.days_to_expiry is not None and info.days_to_expiry <= 21:
            findings.append(Finding(
                title="TLS certificate expiring soon", asset=asset,
                evidence=f"{info.days_to_expiry} days remaining (notAfter={info.not_after})",
                description="The TLS certificate will expire within three weeks.",
                why_it_matters="Imminent expiry causes outages/trust errors if not renewed.",
                severity=Severity.LOW, confidence=Confidence.HIGH,
                remediation="Renew the certificate and verify auto-renewal.",
                validation=ValidationState.CONFIRMED, source="tls-probe", category="tls",
            ))

        if info.self_signed:
            info.problems.append("self-signed certificate")
            findings.append(Finding(
                title="Self-signed TLS certificate", asset=asset,
                evidence=f"subject == issuer ({info.subject})",
                description="The certificate is self-signed (not issued by a trusted CA).",
                why_it_matters="Cannot be validated by clients; enables trust-on-first-use MITM.",
                severity=Severity.LOW, confidence=Confidence.HIGH,
                remediation="Use a certificate from a trusted CA (e.g. ACME/Let's Encrypt).",
                validation=ValidationState.CONFIRMED, source="tls-probe", category="tls",
            ))

        if info.hostname_match is False:
            info.problems.append("hostname mismatch")
            findings.append(Finding(
                title="TLS certificate hostname mismatch", asset=asset,
                evidence=f"expected {host.hostnames[0]}, SANs={info.sans}",
                description="The certificate does not cover the host's DNS name.",
                why_it_matters="Clients reject or warn; may indicate mis-issued/shared certificate.",
                severity=Severity.LOW, confidence=Confidence.MEDIUM,
                remediation="Issue a certificate whose SANs include the served hostname.",
                validation=ValidationState.POTENTIAL, source="tls-probe", category="tls",
            ))

        weak = [p for p in info.protocols_offered if p in _WEAK_PROTOCOLS]
        if weak:
            info.problems.append(f"weak protocols: {', '.join(weak)}")
            findings.append(Finding(
                title="Deprecated TLS protocol versions enabled", asset=asset,
                evidence=f"accepted: {', '.join(weak)}",
                description="The service negotiates deprecated TLS versions.",
                why_it_matters="TLS 1.0/1.1 have known weaknesses and are disallowed by PCI/modern baselines.",
                severity=Severity.MEDIUM, confidence=Confidence.HIGH,
                impact="Downgrade attacks; non-compliance.",
                remediation="Disable TLS 1.0/1.1 (and SSLv3); require TLS 1.2+.",
                validation=ValidationState.CONFIRMED, source="tls-probe", category="tls",
            ))
        return findings


def _wildcard_match(name: str, pattern: str) -> bool:
    if not pattern.startswith("*."):
        return False
    return name.split(".", 1)[-1] == pattern[2:]

"""LDAP probe — anonymous bind + RootDSE (read-only).

Attempts an anonymous LDAP simple bind and, if allowed, a base-scoped RootDSE
search for public directory metadata (naming contexts, DNS host name, domain
functional level). This is standard, non-destructive AD/LDAP reconnaissance:
no credentials guessed, nothing written, only the RootDSE (which is designed to
be world-readable) is queried.
"""
from __future__ import annotations

import socket
import ssl

from .. import ber
from ..models import Confidence, Finding, Host, Port, Severity, ValidationState
from .base import ProbeResult, ServiceProbe

_ROOTDSE_ATTRS = [
    "namingContexts", "defaultNamingContext", "dnsHostName",
    "domainFunctionality", "forestFunctionality", "supportedLDAPVersion",
    "rootDomainNamingContext",
]


def _bind_request(msgid: int) -> bytes:
    # [APPLICATION 0] { version(3), name(""), [0] simple("") }
    op = ber.tlv(0x60, ber.int_tlv(3) + ber.octet_tlv("") + ber.tlv(0x80, b""))
    return ber.seq(ber.int_tlv(msgid), op)


def _search_rootdse(msgid: int) -> bytes:
    attrs = ber.seq(*[ber.octet_tlv(a) for a in _ROOTDSE_ATTRS])
    body = (ber.octet_tlv("")           # baseObject ""
            + ber.enum_tlv(0)           # scope: baseObject
            + ber.enum_tlv(0)           # derefAliases: never
            + ber.int_tlv(0)            # sizeLimit
            + ber.int_tlv(0)            # timeLimit
            + ber.tlv(0x01, b"\x00")    # typesOnly: false
            + ber.tlv(0x87, b"objectClass")  # filter: present(objectClass)
            + attrs)
    op = ber.tlv(0x63, body)            # [APPLICATION 3] searchRequest
    return ber.seq(ber.int_tlv(msgid), op)


class LDAPProbe(ServiceProbe):
    name = "ldap"

    def matches(self, port: Port) -> bool:
        return port.service.name in ("ldap", "ldaps") or port.number in (389, 636)

    def probe(self, host: Host, port: Port) -> ProbeResult:
        ip, num = host.ip, port.number
        if not self.in_scope(ip, num):
            return ProbeResult(error="scope denied")
        use_tls = num == 636 or port.service.name == "ldaps"
        with self.scope.slot(ip, num) as s:
            if not s.allowed:
                return ProbeResult(error="scope denied")
            sock = None
            try:
                sock = socket.create_connection((ip, num), timeout=self.config.timeout)
                if use_tls:
                    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
                    ctx.check_hostname = False
                    ctx.verify_mode = ssl.CERT_NONE
                    sock = ctx.wrap_socket(sock, server_hostname=ip)
                sock.sendall(_bind_request(1))
                resp = self._recv(sock)
                result_code = self._bind_result(resp)
                if result_code is None:
                    return ProbeResult(error="no/invalid bind response")
                if result_code != 0:
                    port.service.name = "ldap"
                    port.service.confidence = Confidence.HIGH
                    return ProbeResult(data={"ldap": {"anonymous_bind": False,
                                                      "result_code": result_code}})
                # anonymous bind succeeded -> query RootDSE
                sock.sendall(_search_rootdse(2))
                sresp = self._recv(sock)
                attrs = self._scrape_rootdse(sresp)
            except (ssl.SSLError, socket.timeout, OSError) as exc:
                return ProbeResult(error=str(exc))
            finally:
                if sock is not None:
                    try:
                        sock.close()
                    except OSError:
                        pass

        port.service.name = "ldaps" if use_tls else "ldap"
        port.service.confidence = Confidence.HIGH
        return self._build(host, port, attrs)

    # -- io / parsing ----------------------------------------------------- #
    def _recv(self, sock, limit: int = 8192) -> bytes:
        buf = b""
        sock.settimeout(min(self.config.timeout, 3.0))
        try:
            while len(buf) < limit:
                chunk = sock.recv(4096)
                if not chunk:
                    break
                buf += chunk
                # stop once we have at least one complete top-level TLV
                res = ber.parse_tlv(buf)
                if res and res[2] <= len(buf):
                    break
        except (socket.timeout, OSError):
            pass
        return buf

    def _bind_result(self, data: bytes):
        res = ber.parse_tlv(data)
        if not res or res[0] != ber.SEQUENCE:
            return None
        for tag, val in ber.children(res[1]):
            if tag == 0x61:  # [APPLICATION 1] bindResponse
                inner = ber.parse_tlv(val)
                if inner and inner[0] == ber.ENUMERATED:
                    return ber.decode_int(inner[1])
                # resultCode is first child
                for t2, v2 in ber.children(val):
                    if t2 == ber.ENUMERATED:
                        return ber.decode_int(v2)
        return None

    def _scrape_rootdse(self, data: bytes) -> dict:
        """Best-effort: pull printable attribute type/value strings."""
        strings = [s.decode("latin-1", "replace")
                   for s in ber.find_octet_strings(data) if s]
        attrs: dict[str, list[str]] = {}
        known = set(a.lower() for a in _ROOTDSE_ATTRS)
        current = None
        for s in strings:
            if s.lower() in known:
                current = s
                attrs.setdefault(current, [])
            elif current is not None:
                attrs[current].append(s)
        # also capture any naming-context-looking values
        ncs = [s for s in strings if s.upper().startswith(("DC=", "CN=", "OU="))]
        if ncs and "namingContexts" not in attrs:
            attrs["namingContexts"] = ncs
        return attrs

    def _build(self, host, port, attrs) -> ProbeResult:
        asset = f"{host.ip}:{port.number}"
        ncs = attrs.get("namingContexts", []) or attrs.get("defaultNamingContext", [])
        dns_host = attrs.get("dnsHostName", [])
        looks_like_dc = bool(ncs and any("DC=" in n.upper() for n in ncs))
        evidence_bits = []
        if ncs:
            evidence_bits.append("namingContexts=" + ", ".join(ncs[:3]))
        if dns_host:
            evidence_bits.append("dnsHostName=" + dns_host[0])
        evidence = "; ".join(evidence_bits) or "anonymous bind succeeded (RootDSE readable)"

        findings = [Finding(
            title="LDAP anonymous bind allowed", asset=asset,
            evidence=evidence,
            description="The LDAP service accepts an anonymous simple bind and "
                        "returns RootDSE metadata.",
            why_it_matters="Anonymous LDAP exposes directory structure (and often "
                           "user/group data on deeper queries), aiding targeting; "
                           "on Active Directory it reveals domain/forest details.",
            severity=Severity.MEDIUM, confidence=Confidence.HIGH,
            impact="Directory/domain information disclosure to unauthenticated clients.",
            remediation="Disable anonymous binds; require authenticated LDAP and "
                        "restrict access to trusted networks.",
            validation=ValidationState.CONFIRMED, source="ldap-probe",
            category="exposure",
        )]
        if looks_like_dc:
            host.notes.append("LDAP RootDSE indicates an Active Directory domain "
                              "controller: " + ", ".join(ncs[:2]))
            findings.append(Finding(
                title="Active Directory Domain Controller detected", asset=asset,
                evidence="; ".join(evidence_bits) or "AD-style namingContexts present",
                description="RootDSE naming contexts indicate this host is an "
                            "Active Directory Domain Controller.",
                why_it_matters="Domain Controllers are high-value targets; exposure "
                               "of AD services to untrusted networks is high-risk.",
                severity=Severity.MEDIUM, confidence=Confidence.MEDIUM,
                impact="Identifies core identity infrastructure and its reachability.",
                remediation="Ensure DC services (LDAP/Kerberos/SMB) are not reachable "
                            "from untrusted networks; enforce least exposure.",
                validation=ValidationState.OBSERVED, source="ldap-probe",
                category="exposure",
            ))
        return ProbeResult(data={"ldap": {"anonymous_bind": True, "rootdse": attrs}},
                           findings=findings)

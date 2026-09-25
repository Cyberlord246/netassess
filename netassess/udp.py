"""UDP scanning + SNMP / NTP analysis (read-only, scope-gated).

UDP is connectionless, so a blind empty packet rarely elicits a reply. We send a
*protocol-appropriate* payload per port and read the response:

  * response bytes            -> OPEN (and we can often identify/probe the service)
  * ICMP port-unreachable     -> CLOSED (surfaces as a socket error on recv)
  * nothing (timeout)         -> OPEN|FILTERED (ambiguous — recorded low-confidence)

Everything is read-only: an SNMP GET, an NTP query, a DNS query. No writes, no
SNMP SET, no credential attacks. Every packet passes the Scope Engine.
"""
from __future__ import annotations

import random
import socket
import struct
import time
from concurrent.futures import ThreadPoolExecutor, as_completed

from . import ber
from .config import Config
from .models import (
    Confidence, Finding, Port, PortState, Service, Severity, ValidationState,
)
from .scope import ScopeEngine

DEFAULT_UDP_PORTS = [53, 123, 161, 137, 500, 1900, 5353, 69, 111, 623]

SNMP_COMMUNITIES = ["public", "private"]
_SYSDESCR_OID = "1.3.6.1.2.1.1.1.0"


# --------------------------------------------------------------------------- #
# protocol payloads
# --------------------------------------------------------------------------- #
def build_snmp_get(community: str, oid: str = _SYSDESCR_OID,
                   request_id: int | None = None) -> bytes:
    rid = request_id if request_id is not None else random.randint(1, 0x7FFFFFFF)
    varbind = ber.seq(ber.oid_tlv(oid), ber.null_tlv())
    varbinds = ber.seq(varbind)
    pdu = ber.tlv(0xA0,  # GetRequest
                  ber.int_tlv(rid) + ber.int_tlv(0) + ber.int_tlv(0) + varbinds)
    return ber.seq(ber.int_tlv(1),          # version 1 == SNMPv2c
                   ber.octet_tlv(community),
                   pdu)


def parse_snmp_sysdescr(data: bytes) -> str | None:
    """Return the sysDescr string from a GetResponse, or None."""
    res = ber.parse_tlv(data)
    if not res or res[0] != ber.SEQUENCE:
        return None
    # scrape octet strings; skip the community string (first one)
    strings = ber.find_octet_strings(res[1])
    # community is typically the first octet string; sysDescr the next non-empty
    candidates = [s for s in strings[1:] if s and _mostly_printable(s)]
    if candidates:
        return candidates[0].decode("latin-1", "replace")
    return None


def build_ntp_request() -> bytes:
    # LI=0, VN=4, Mode=3 (client) -> 0x23; 48-byte packet
    return b"\x23" + b"\x00" * 47


def parse_ntp(data: bytes) -> dict | None:
    if len(data) < 4:
        return None
    b0 = data[0]
    return {"leap": (b0 >> 6) & 0x3, "version": (b0 >> 3) & 0x7,
            "mode": b0 & 0x7, "stratum": data[1]}


# classic ntpdc MON_GETLIST_1 request (mode 7) — detection only
_NTP_MONLIST = b"\x17\x00\x03\x2a" + b"\x00" * 4


def build_dns_query(name: str = "version.bind", qtype: int = 16,
                    qclass: int = 3) -> bytes:
    tid = random.randint(0, 0xFFFF).to_bytes(2, "big")
    header = tid + b"\x00\x00" + b"\x00\x01" + b"\x00\x00" * 3
    q = b""
    for label in name.split("."):
        q += bytes([len(label)]) + label.encode()
    q += b"\x00" + struct.pack("!HH", qtype, qclass)
    return header + q


_NETBIOS_STAT = (b"\x00\x00\x00\x10\x00\x01\x00\x00\x00\x00\x00\x00"
                 + b"\x20CKAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA\x00\x00\x21\x00\x01")
_SSDP = (b"M-SEARCH * HTTP/1.1\r\nHOST:239.255.255.250:1900\r\n"
         b"MAN:\"ssdp:discover\"\r\nMX:1\r\nST:ssdp:all\r\n\r\n")


def _payload_for(port: int) -> bytes:
    return {
        53: build_dns_query(),
        123: build_ntp_request(),
        161: build_snmp_get("public"),
        137: _NETBIOS_STAT,
        1900: _SSDP,
        5353: build_dns_query("_services._dns-sd._udp.local", 12, 1),
    }.get(port, b"\x00")


def _mostly_printable(b: bytes) -> bool:
    if not b:
        return False
    printable = sum(1 for c in b if 32 <= c < 127 or c in (9, 10, 13))
    return printable / len(b) > 0.7


# --------------------------------------------------------------------------- #
# scanner
# --------------------------------------------------------------------------- #
class UDPScanner:
    def __init__(self, config: Config, scope: ScopeEngine):
        self.config = config
        self.scope = scope

    def _send_recv(self, ip: str, port: int, payload: bytes):
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        sock.settimeout(self.config.timeout)
        try:
            sock.sendto(payload, (ip, port))
            data, _ = sock.recvfrom(4096)
            return "open", data
        except socket.timeout:
            return "open|filtered", b""
        except (ConnectionResetError, ConnectionRefusedError, OSError):
            # ICMP port unreachable typically surfaces here -> closed
            return "closed", b""
        finally:
            try:
                sock.close()
            except OSError:
                pass

    def scan_port(self, ip: str, port: int) -> Port | None:
        with self.scope.slot(ip, port) as s:
            if not s.allowed:
                return None
            state, data = self._send_recv(ip, port, _payload_for(port))
        if state == "closed":
            return None
        svc = Service(protocol="udp")
        p = Port(number=port, protocol="udp", service=svc)
        if state == "open":
            p.state = PortState.OPEN
            svc.confidence = Confidence.MEDIUM
            if data:
                svc.banner = data[:64].hex()
            p.service.evidence = "udp response"
            p._response = data  # transient, used by analyzers
        else:
            p.state = PortState.OPEN_FILTERED
            svc.confidence = Confidence.LOW
            p._response = b""
        return p

    def scan_host(self, ip: str, ports: list[int]) -> list[Port]:
        found = []
        with ThreadPoolExecutor(max_workers=max(2, self.config.concurrency // 2)) as pool:
            futs = {pool.submit(self.scan_port, ip, p): p for p in ports}
            for f in as_completed(futs):
                r = f.result()
                if r is not None:
                    found.append(r)
        found.sort(key=lambda x: x.number)
        return found

    # -- analysis of open UDP ports -> findings --------------------------- #
    def analyze(self, ip: str, port: Port) -> list[Finding]:
        num = port.number
        data = getattr(port, "_response", b"")
        if num == 161:
            return self._analyze_snmp(ip, port, data)
        if num == 123:
            return self._analyze_ntp(ip, port, data)
        # generic service naming
        names = {53: "dns", 137: "netbios-ns", 500: "isakmp", 1900: "ssdp",
                 5353: "mdns", 69: "tftp", 111: "rpcbind", 623: "ipmi-rmcp"}
        if num in names:
            port.service.name = names[num]
        return []

    def _analyze_snmp(self, ip, port, data) -> list[Finding]:
        port.service.name = "snmp"
        findings = []
        # the default-"public" GET was already sent; if we got a response, parse it
        sysdescr = parse_snmp_sysdescr(data) if data else None
        working_community = "public" if sysdescr else None
        if not sysdescr:
            # try 'private' explicitly
            with self.scope.slot(ip, 161) as s:
                if s.allowed:
                    st, d2 = self._send_recv(ip, 161, build_snmp_get("private"))
                    if st == "open" and d2:
                        sysdescr = parse_snmp_sysdescr(d2)
                        if sysdescr:
                            working_community = "private"
        if working_community:
            port.service.product = (sysdescr or "")[:120]
            port.service.confidence = Confidence.HIGH
            findings.append(Finding(
                title=f"SNMP accessible with default community '{working_community}'",
                asset=f"{ip}:161/udp",
                evidence=f"GET sysDescr returned: {sysdescr!r}"[:300],
                description="The SNMP service responds to a default community string.",
                why_it_matters="Default SNMP communities expose system inventory, "
                               "interfaces, routes and more, aiding targeting; "
                               "read-write communities can allow config changes.",
                severity=Severity.HIGH, confidence=Confidence.HIGH,
                impact="Information disclosure; potential device reconfiguration if RW.",
                remediation="Disable SNMP if unused; use SNMPv3 with auth+priv; "
                            "replace default community strings; restrict by ACL.",
                validation=ValidationState.CONFIRMED, source="snmp-probe",
                category="exposure",
            ))
        else:
            findings.append(Finding(
                title="SNMP service reachable", asset=f"{ip}:161/udp",
                evidence="UDP/161 responded or is open",
                description="An SNMP service is reachable (default communities "
                            "did not return data).",
                why_it_matters="SNMP exposed to untrusted networks is an "
                               "information-disclosure and amplification vector.",
                severity=Severity.MEDIUM, confidence=Confidence.MEDIUM,
                remediation="Restrict SNMP to trusted management networks; prefer SNMPv3.",
                validation=ValidationState.OBSERVED, source="snmp-probe",
                category="exposure",
            ))
        return findings

    def _analyze_ntp(self, ip, port, data) -> list[Finding]:
        port.service.name = "ntp"
        findings = []
        info = parse_ntp(data) if data else None
        if info:
            port.service.product = f"NTPv{info['version']} stratum {info['stratum']}"
            port.service.confidence = Confidence.HIGH
        # monlist / mode-7 amplification check (detection only)
        with self.scope.slot(ip, 123) as s:
            if s.allowed:
                st, d2 = self._send_recv(ip, 123, _NTP_MONLIST)
                if st == "open" and d2:
                    findings.append(Finding(
                        title="NTP mode 7 (monlist) enabled", asset=f"{ip}:123/udp",
                        evidence=f"monlist request returned {len(d2)} bytes",
                        description="The NTP server answers ntpdc mode-7 (monlist) "
                                    "requests.",
                        why_it_matters="monlist is a large UDP amplification vector "
                                       "(CVE-2013-5211) and leaks recent client IPs.",
                        severity=Severity.HIGH, confidence=Confidence.HIGH,
                        impact="Usable in DDoS reflection/amplification; info disclosure.",
                        remediation="Disable mode 7 / monlist (noquery), update ntpd, "
                                    "or restrict queries.",
                        validation=ValidationState.CONFIRMED, source="ntp-probe",
                        category="exposure",
                    ))
        if not findings and info:
            findings.append(Finding(
                title="NTP service reachable", asset=f"{ip}:123/udp",
                evidence=f"NTPv{info['version']}, stratum {info['stratum']}",
                description="A reachable NTP server.",
                why_it_matters="Publicly reachable NTP can be abused for "
                               "amplification if misconfigured.",
                severity=Severity.LOW, confidence=Confidence.MEDIUM,
                remediation="Restrict NTP to needed clients; disable query modes.",
                validation=ValidationState.OBSERVED, source="ntp-probe",
                category="exposure",
            ))
        return findings

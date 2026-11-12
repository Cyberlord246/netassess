"""Additional safe service probes: SSH, SMTP, DNS, SMB, Database, Generic.

All are read-only banner/metadata probes. None attempt authentication, none
send credentials, none mutate remote state. Each re-checks scope before every
connection.
"""
from __future__ import annotations

import re
import socket
import ssl
import struct

from ..models import Confidence, Finding, Host, Port, Service, Severity, ValidationState
from ..services import set_service_version, split_software
from .base import ProbeResult, ServiceProbe

# --- banner -> (product, version) extraction (feeds the CVE engine) --------- #
_VER = r"(\d+(?:\.\d+)+[a-z0-9._-]*)"
_BANNER_PRODUCTS = [
    ("vsftpd", r"vsftpd"), ("proftpd", r"proftpd"), ("pure-ftpd", r"pure-?ftpd"),
    ("filezilla", r"filezilla"), ("microsoft ftpd", r"microsoft ftp"),
    ("dovecot", r"dovecot"), ("courier", r"courier"), ("cyrus", r"cyrus"),
    ("exim", r"exim"), ("postfix", r"postfix"), ("sendmail", r"sendmail"),
    ("microsoft esmtp", r"microsoft esmtp"), ("openssh", r"openssh"),
]


def banner_product_version(banner: str) -> tuple[str, str]:
    """Best-effort (product, version) from a service banner.

    The version is read only from text AFTER the product name, so a hostname or
    IP earlier in the banner ("220 10.0.0.5 ESMTP Exim 4.94.2") is never
    mistaken for the version. No recognised product -> no version."""
    for name, rx in _BANNER_PRODUCTS:
        pm = re.search(rx, banner, re.I)
        if pm:
            m = re.search(_VER, banner[pm.end():])
            return name, (m.group(1) if m else "")
    return "", ""


def parse_mysql_greeting(data: bytes) -> tuple[str, str]:
    """MySQL/MariaDB send the version in cleartext in the initial handshake."""
    if len(data) < 6 or data[4] != 0x0A:      # protocol version 10
        return "", ""
    end = data.find(b"\x00", 5)
    if end == -1:
        return "", ""
    ver = data[5:end].decode("latin-1", "replace")
    prod = "mariadb" if "mariadb" in ver.lower() else "mysql"
    return prod, ver


def _recv_banner(scope, config, ip, port, send=b"", read=512, wait_first=True):
    with scope.slot(ip, port) as s:
        if not s.allowed:
            return None, "scope denied"
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(config.timeout)
        try:
            sock.connect((ip, port))
            if send:
                sock.sendall(send)
            data = sock.recv(read)
            return data, ""
        except (socket.timeout, OSError) as exc:
            return None, str(exc)
        finally:
            try:
                sock.close()
            except OSError:
                pass


def _recv_banner_maybe_tls(scope, config, ip, port, tls: bool, read=512):
    """Read a service banner, wrapping in TLS first for implicit-TLS ports."""
    if not tls:
        return _recv_banner(scope, config, ip, port, read=read)
    with scope.slot(ip, port) as s:
        if not s.allowed:
            return None, "scope denied"
        sock = None
        try:
            raw = socket.create_connection((ip, port), timeout=config.timeout)
            ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
            ctx.check_hostname = False
            ctx.verify_mode = ssl.CERT_NONE
            sock = ctx.wrap_socket(raw, server_hostname=None)
            sock.settimeout(config.timeout)
            return sock.recv(read), ""
        except (ssl.SSLError, socket.timeout, OSError) as exc:
            return None, str(exc)
        finally:
            if sock is not None:
                try:
                    sock.close()
                except OSError:
                    pass


class _BannerVersionProbe(ServiceProbe):
    """Shared base: read a (optionally TLS) banner, extract product/version so the
    CVE engine can match it. Findings (CVE/KEV) then aggregate by title across
    hosts automatically."""
    svc_name = "service"
    ports: tuple = ()
    tls_ports: tuple = ()

    def matches(self, port: Port) -> bool:
        return port.number in self.ports or port.number in self.tls_ports \
            or port.service.name == self.svc_name

    def probe(self, host: Host, port: Port) -> ProbeResult:
        tls = port.number in self.tls_ports
        data, err = _recv_banner_maybe_tls(self.scope, self.config, host.ip,
                                           port.number, tls)
        if data is None:
            return ProbeResult(error=err)
        banner = data.decode("latin-1", "replace").strip()
        prod, ver = banner_product_version(banner)
        port.service.name = self.svc_name
        port.service.banner = banner[:200]
        set_service_version(port, prod, ver,
                            confidence=Confidence.HIGH if (prod or ver) else None)
        return ProbeResult(data={self.svc_name: {"banner": banner[:200],
                                                 "product": prod, "version": ver}})


class FTPProbe(_BannerVersionProbe):
    name = "ftp"
    svc_name = "ftp"
    ports = (21,)
    tls_ports = (990,)


class IMAPProbe(_BannerVersionProbe):
    name = "imap"
    svc_name = "imap"
    ports = (143,)
    tls_ports = (993,)


class POP3Probe(_BannerVersionProbe):
    name = "pop3"
    svc_name = "pop3"
    ports = (110,)
    tls_ports = (995,)


class SSHProbe(ServiceProbe):
    name = "ssh"

    def matches(self, port: Port) -> bool:
        return port.service.name == "ssh" or port.number == 22

    def probe(self, host: Host, port: Port) -> ProbeResult:
        data, err = _recv_banner(self.scope, self.config, host.ip, port.number)
        if data is None:
            return ProbeResult(error=err)
        banner = data.decode("latin-1", errors="replace").strip()
        info = {"banner": banner}
        findings = []
        if banner.startswith("SSH-"):
            parts = banner.split("-", 2)
            proto_ver = parts[1] if len(parts) > 1 else ""
            software = parts[2] if len(parts) > 2 else ""
            info["protocol_version"] = proto_ver
            info["software"] = software
            port.service.name = "ssh"
            sw_prod, sw_ver = split_software(software)
            set_service_version(port, sw_prod or software, sw_ver,
                                evidence=f"SSH banner: {banner[:120]}",
                                confidence=Confidence.HIGH)
            port.service.banner = banner
            if proto_ver.startswith("1."):
                findings.append(Finding(
                    title="Obsolete SSH protocol version 1 offered",
                    asset=f"{host.ip}:{port.number}", evidence=banner,
                    description="The SSH service advertises protocol version 1.",
                    why_it_matters="SSHv1 is cryptographically broken and must not be used.",
                    severity=Severity.HIGH, confidence=Confidence.HIGH,
                    remediation="Disable SSH protocol 1; require protocol 2 only.",
                    validation=ValidationState.CONFIRMED, source="ssh-probe", category="crypto",
                ))
        return ProbeResult(data={"ssh": info}, findings=findings)


def _mqtt_remaining_len(n: int) -> bytes:
    out = bytearray()
    while True:
        d = n % 128
        n //= 128
        if n > 0:
            d |= 0x80
        out.append(d)
        if n == 0:
            return bytes(out)


def mqtt_connect_packet(client_id: bytes = b"netassess") -> bytes:
    """A minimal MQTT 3.1.1 CONNECT (clean session, no credentials)."""
    var_header = b"\x00\x04MQTT\x04\x02" + struct.pack(">H", 60)
    payload = struct.pack(">H", len(client_id)) + client_id
    body = var_header + payload
    return b"\x10" + _mqtt_remaining_len(len(body)) + body


# MQTT 3.1.1 CONNACK return codes
_MQTT_RC = {
    0: "connection accepted (anonymous access allowed)",
    1: "unacceptable protocol version",
    2: "identifier rejected",
    3: "server unavailable",
    4: "bad username/password",
    5: "not authorized",
}


class MQTTProbe(ServiceProbe):
    name = "mqtt"

    def matches(self, port: Port) -> bool:
        return port.service.name in ("mqtt", "mqtts") or port.number in (1883, 8883)

    def probe(self, host: Host, port: Port) -> ProbeResult:
        ip, num = host.ip, port.number
        use_tls = num == 8883 or port.service.name == "mqtts"
        with self.scope.slot(ip, num) as s:
            if not s.allowed:
                return ProbeResult(error="scope denied")
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(self.config.timeout)
            try:
                sock.connect((ip, num))
                if use_tls:
                    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
                    ctx.check_hostname = False
                    ctx.verify_mode = ssl.CERT_NONE
                    sock = ctx.wrap_socket(sock, server_hostname=None)
                sock.sendall(mqtt_connect_packet())
                resp = sock.recv(16)
            except (socket.timeout, OSError, ssl.SSLError) as exc:
                return ProbeResult(error=str(exc))
            finally:
                try:
                    sock.close()
                except OSError:
                    pass
        # CONNACK = 0x20, remaining length 0x02, [session_present, return_code]
        if len(resp) < 4 or (resp[0] & 0xF0) != 0x20:
            return ProbeResult(error="not an MQTT broker")
        rc = resp[3]
        port.service.name = "mqtts" if use_tls else "mqtt"
        set_service_version(port, "MQTT broker", confidence=Confidence.HIGH)
        info = {"connack_rc": rc, "meaning": _MQTT_RC.get(rc, f"code {rc}")}
        findings = []
        if rc == 0:
            findings.append(Finding(
                title="MQTT broker allows anonymous connection",
                asset=f"{ip}:{num}",
                evidence=f"CONNECT with no credentials returned CONNACK rc=0 "
                         f"({'TLS' if use_tls else 'plaintext'})",
                description="The MQTT broker accepted an unauthenticated CONNECT.",
                why_it_matters="Anyone reachable can subscribe to/publish on "
                               "topics — often sensor data, commands, or PII.",
                severity=Severity.HIGH, confidence=Confidence.HIGH,
                impact="Unauthorised read/write of MQTT topics.",
                remediation="Require authentication (username/password or mTLS) "
                            "and ACLs; restrict network exposure.",
                validation=ValidationState.CONFIRMED,
                source="mqtt-probe", category="exposure"))
        return ProbeResult(data={"mqtt": info}, findings=findings)


class SMTPProbe(ServiceProbe):
    name = "smtp"

    def matches(self, port: Port) -> bool:
        return port.service.name in ("smtp", "smtps", "smtp-submission") or \
            port.number in (25, 465, 587)

    def probe(self, host: Host, port: Port) -> ProbeResult:
        # read greeting, then a benign EHLO to learn capabilities (incl. STARTTLS)
        data, err = _recv_banner(self.scope, self.config, host.ip, port.number,
                                 send=b"EHLO netassess.local\r\n", read=1024)
        if data is None:
            return ProbeResult(error=err)
        text = data.decode("latin-1", errors="replace")
        caps = [ln[4:].strip() for ln in text.splitlines() if len(ln) > 4]
        starttls = any("STARTTLS" in c.upper() for c in caps)
        greeting = text.splitlines()[0] if text else ""
        info = {"banner": greeting, "capabilities": caps, "starttls": starttls}
        port.service.name = "smtp"
        if greeting and not port.service.banner:
            port.service.banner = greeting[:200]
        # "220 mx.example.com ESMTP Exim 4.94.2" / "... ESMTP Postfix (Ubuntu)"
        prod, ver = banner_product_version(greeting)
        set_service_version(port, prod, ver, confidence=Confidence.HIGH)
        findings = []
        if port.number in (25, 587) and not starttls:
            findings.append(Finding(
                title="SMTP service without STARTTLS", asset=f"{host.ip}:{port.number}",
                evidence="EHLO response did not advertise STARTTLS",
                description="The SMTP service does not offer opportunistic TLS.",
                why_it_matters="Mail submission/transfer may occur in cleartext.",
                severity=Severity.LOW, confidence=Confidence.MEDIUM,
                remediation="Enable STARTTLS (or implicit TLS on 465) for the MTA.",
                validation=ValidationState.POTENTIAL, source="smtp-probe", category="crypto",
            ))

        # optional, opt-in open-relay test (non-destructive: aborts before DATA)
        if getattr(self.config, "smtp_relay_test", False) and port.number in (25, 587):
            relay = self._relay_test(host.ip, port.number)
            info["relay_test"] = relay
            if relay.get("open_relay"):
                findings.append(Finding(
                    title="SMTP open relay", asset=f"{host.ip}:{port.number}",
                    evidence=relay.get("evidence", ""),
                    description="The MTA accepted a message from an external sender to "
                                "an external recipient without authentication "
                                "(relay transaction was aborted before DATA — no mail sent).",
                    why_it_matters="Open relays are abused to send spam/phishing, get the "
                                   "server blacklisted, and can spoof internal mail.",
                    severity=Severity.HIGH, confidence=Confidence.HIGH,
                    impact="Third parties can relay arbitrary mail through this server.",
                    remediation="Restrict relaying to authenticated users / trusted "
                                "networks only; deny external->external relay.",
                    validation=ValidationState.CONFIRMED, source="smtp-probe",
                    category="mail-relay",
                ))
        return ProbeResult(data={"smtp": info}, findings=findings)

    def _relay_test(self, ip: str, port: int) -> dict:
        """Non-destructive open-relay check: offer an external sender+recipient and
        read whether RCPT is accepted, then RSET/QUIT. DATA is never sent, so no
        message is ever transmitted even if the server would accept it."""
        with self.scope.slot(ip, port) as s:
            if not s.allowed:
                return {"open_relay": False, "evidence": "scope denied"}
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(self.config.timeout)
            try:
                sock.connect((ip, port))
                self._readline(sock)                       # 220 greeting
                self._cmd(sock, b"EHLO netassess.local")
                mail = self._cmd(sock, b"MAIL FROM:<relaytest@example.com>")
                rcpt = self._cmd(sock, b"RCPT TO:<relaytest@example.org>")
                self._cmd(sock, b"RSET")                   # abort the transaction
                self._cmd(sock, b"QUIT")
                code = rcpt[:3]
                allowed = code in (b"250", b"251")
                return {
                    "open_relay": allowed,
                    "mail_from_response": mail.decode("latin-1", "replace").strip()[:120],
                    "rcpt_to_response": rcpt.decode("latin-1", "replace").strip()[:120],
                    "evidence": (f"RCPT TO external recipient accepted: "
                                 f"{rcpt.decode('latin-1','replace').strip()[:120]}"
                                 if allowed else
                                 f"relay denied: {rcpt.decode('latin-1','replace').strip()[:80]}"),
                }
            except OSError as exc:
                return {"open_relay": False, "evidence": f"error: {exc}"}
            finally:
                try:
                    sock.close()
                except OSError:
                    pass

    @staticmethod
    def _readline(sock) -> bytes:
        try:
            return sock.recv(512)
        except OSError:
            return b""

    def _cmd(self, sock, line: bytes) -> bytes:
        sock.sendall(line + b"\r\n")
        return self._readline(sock)


def _dns_qname(name: str) -> bytes:
    out = b""
    for lbl in name.rstrip(".").split("."):
        if lbl:
            enc = lbl.encode("latin-1", "ignore")[:63]
            out += bytes([len(enc)]) + enc
    return out + b"\x00"


def dns_query(qname: str, qtype: int, *, rd: bool = True, tid: int = 0x1337) -> bytes:
    flags = 0x0100 if rd else 0x0000            # RD bit
    header = struct.pack("!HHHHHH", tid, flags, 1, 0, 0, 0)
    return header + _dns_qname(qname) + struct.pack("!HH", qtype, 1)  # class IN


def _reverse_zone(ip: str) -> str:
    """The /24 reverse zone for an IPv4 address (a.b.c.d -> c.b.a.in-addr.arpa)."""
    parts = ip.split(".")
    if len(parts) == 4 and all(p.isdigit() for p in parts):
        return f"{parts[2]}.{parts[1]}.{parts[0]}.in-addr.arpa"
    return ""


class DNSProbe(ServiceProbe):
    name = "dns"

    def matches(self, port: Port) -> bool:
        return port.service.name == "dns" or port.number == 53

    def probe(self, host: Host, port: Port) -> ProbeResult:
        ip, num = host.ip, port.number
        # 1) version.bind (CH TXT over TCP) — read-only identification
        framed = struct.pack("!H", len(self._build_version_query())) \
            + self._build_version_query()
        data, _ = _recv_banner(self.scope, self.config, ip, num,
                               send=framed, read=512)
        info = {"tcp_dns": data is not None}
        version = ""
        if data and len(data) > 2:
            try:
                version = self._extract_txt(data[2:])
            except (struct.error, IndexError):
                version = ""
        if version:
            info["version.bind"] = version
            dprod, dver = split_software(version)
            # BIND answers version.bind with a bare number ("9.18.18-…-Ubuntu");
            # others name themselves ("dnsmasq-2.86", "unbound 1.13.1").
            set_service_version(port, dprod or ("ISC BIND" if dver else version),
                                dver, evidence=f"version.bind: {version[:120]}",
                                confidence=Confidence.HIGH)
        port.service.name = "dns"
        findings = []

        # 2) open recursion / open resolver — recursive query for an external name
        if self._recursion_open(ip, num):
            info["open_recursion"] = True
            findings.append(Finding(
                title="DNS open recursion (open resolver)",
                asset=f"{ip}:{num}",
                evidence="recursive query for an external name (example.com) was "
                         "answered with RA=1",
                description="The DNS server recursively resolves names for "
                            "arbitrary clients.",
                why_it_matters="Open resolvers are abused for DNS amplification "
                               "DDoS and cache-poisoning.",
                severity=Severity.MEDIUM, confidence=Confidence.HIGH,
                impact="Reflection/amplification DDoS participation; cache abuse.",
                remediation="Disable recursion for untrusted clients (views/ACLs) "
                            "or restrict to internal networks.",
                validation=ValidationState.CONFIRMED, source="dns-probe",
                category="misconfiguration"))

        # 3) zone transfer (AXFR) on candidate zones derived from names/reverse zone
        for zone in self._candidate_zones(host):
            n = self._axfr_records(ip, num, zone)
            if n >= 2:                           # SOA + >=1 record == transfer ok
                info.setdefault("axfr", []).append({"zone": zone, "records": n})
                findings.append(Finding(
                    title="DNS zone transfer (AXFR) allowed",
                    asset=f"{ip}:{num}",
                    evidence=f"AXFR for '{zone}' returned {n} record(s)",
                    description=f"The server allowed a full zone transfer of "
                                f"'{zone}' to an unauthenticated client.",
                    why_it_matters="AXFR dumps every record in the zone — internal "
                                   "hostnames, IPs and infrastructure layout.",
                    severity=Severity.HIGH, confidence=Confidence.HIGH,
                    impact="Full internal DNS disclosure; maps the attack surface.",
                    remediation="Restrict zone transfers to authorized secondaries "
                                "(allow-transfer / TSIG).",
                    validation=ValidationState.CONFIRMED, source="dns-probe",
                    category="info-disclosure"))
                break                            # one confirmed AXFR is enough
        return ProbeResult(data={"dns": info}, findings=findings)

    def _recursion_open(self, ip: str, port: int) -> bool:
        payload = dns_query("example.com", 1, rd=True)   # A, recursion desired
        with self.scope.slot(ip, port) as s:
            if not s.allowed:
                return False
            sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            sock.settimeout(self.config.timeout)
            try:
                sock.sendto(payload, (ip, port))
                resp = sock.recv(1024)
            except OSError:
                return False
            finally:
                try:
                    sock.close()
                except OSError:
                    pass
        if len(resp) < 8:
            return False
        flags = struct.unpack("!H", resp[2:4])[0]
        ra = (flags >> 7) & 1
        rcode = flags & 0xF
        ancount = struct.unpack("!H", resp[6:8])[0]
        return bool(ra) and rcode == 0 and ancount > 0   # recursed for an ext name

    def _candidate_zones(self, host: Host) -> list[str]:
        zones: list[str] = []
        for hn in getattr(host, "hostnames", []) or []:
            if "." in hn.rstrip("."):
                parent = hn.rstrip(".").split(".", 1)[1]
                if parent and parent not in zones:
                    zones.append(parent)
        rz = _reverse_zone(host.ip)
        if rz:
            zones.append(rz)
        return zones[:4]

    def _axfr_records(self, ip: str, port: int, zone: str) -> int:
        payload = dns_query(zone, 252, rd=False)         # AXFR qtype=252
        framed = struct.pack("!H", len(payload)) + payload
        data, _ = _recv_banner(self.scope, self.config, ip, port,
                               send=framed, read=8192)
        if not data or len(data) < 14:
            return 0
        msg = data[2:]                                   # strip TCP length prefix
        flags = struct.unpack("!H", msg[2:4])[0]
        if (flags & 0xF) != 0:                            # RCODE != 0 (e.g. REFUSED)
            return 0
        return struct.unpack("!H", msg[6:8])[0]          # ANCOUNT

    def _build_version_query(self) -> bytes:
        # version.bind CH TXT
        tid = b"\x13\x37"
        flags = b"\x00\x00"
        counts = b"\x00\x01\x00\x00\x00\x00\x00\x00"
        qname = b"\x07version\x04bind\x00"
        qtype = b"\x00\x10"   # TXT
        qclass = b"\x00\x03"  # CH
        return tid + flags + counts + qname + qtype + qclass

    def _extract_txt(self, msg: bytes) -> str:
        # naive: find TXT rdata after the answer section header
        idx = msg.find(b"\x00\x10\x00\x03")  # TXT CH in answer
        if idx == -1:
            return ""
        # skip type(2)+class(2)+ttl(4)+rdlen(2)
        p = idx + 4 + 4
        if p + 2 > len(msg):
            return ""
        rdlen = struct.unpack("!H", msg[p:p+2])[0]
        p += 2
        if p >= len(msg):
            return ""
        txtlen = msg[p]
        return msg[p+1:p+1+txtlen].decode("latin-1", errors="replace")


# SMB2/3 dialect revision -> human version
_SMB2_DIALECTS = {
    0x0202: "SMB 2.0.2", 0x0210: "SMB 2.1", 0x0300: "SMB 3.0",
    0x0302: "SMB 3.0.2", 0x0311: "SMB 3.1.1", 0x02FF: "SMB 2.x (wildcard)",
}


def smb2_negotiate_request() -> bytes:
    """Minimal SMB2 NEGOTIATE over direct TCP (445). No auth, no session setup."""
    dialects = [0x0202, 0x0210, 0x0300, 0x0302, 0x0311]
    hdr = (b"\xfeSMB" + struct.pack("<H", 64) + struct.pack("<H", 0)
           + struct.pack("<I", 0) + struct.pack("<H", 0) + struct.pack("<H", 0)
           + struct.pack("<I", 0) + struct.pack("<I", 0) + struct.pack("<Q", 0)
           + struct.pack("<I", 0) + struct.pack("<I", 0) + struct.pack("<Q", 0)
           + b"\x00" * 16)                       # 64-byte SMB2 header
    body = (struct.pack("<H", 36) + struct.pack("<H", len(dialects))
            + struct.pack("<H", 1) + struct.pack("<H", 0) + struct.pack("<I", 0)
            + b"\x00" * 16 + struct.pack("<I", 0) + struct.pack("<H", 0)
            + struct.pack("<H", 0)
            + b"".join(struct.pack("<H", d) for d in dialects))
    smb = hdr + body
    return struct.pack(">I", len(smb)) + smb    # 4-byte NetBIOS length prefix


def parse_smb2_dialect(data: bytes):
    """Return the negotiated SMB2 dialect revision int, or None."""
    if len(data) < 74 or data[4:8] != b"\xfeSMB":
        return None
    return struct.unpack("<H", data[72:74])[0]   # DialectRevision in NEGOTIATE resp


# well-known SMB1 NEGOTIATE (offers "NT LM 0.12"); a \xffSMB reply == SMBv1 on
_SMB1_NEGOTIATE = (
    b"\x00\x00\x00\x2f\xff\x53\x4d\x42\x72\x00\x00\x00\x00\x18\x53\xc8"
    b"\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\xff\xff\xff\xfe"
    b"\x00\x00\x00\x00\x00\x0c\x00\x02NT LM 0.12\x00")


class SMBProbe(ServiceProbe):
    name = "smb"

    def matches(self, port: Port) -> bool:
        return port.service.name in ("smb", "netbios-ssn", "microsoft-ds") or \
            port.number in (139, 445)

    def _exchange(self, ip: str, port: int, payload: bytes) -> bytes:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(self.config.timeout)
        try:
            sock.connect((ip, port))
            sock.sendall(payload)
            return sock.recv(1024)
        except OSError:
            return b""
        finally:
            try:
                sock.close()
            except OSError:
                pass

    def probe(self, host: Host, port: Port) -> ProbeResult:
        ip, num = host.ip, port.number
        with self.scope.slot(ip, num) as s:
            if not s.allowed:
                return ProbeResult(error="scope denied")
            # 1) SMB2/3 negotiate -> dialect/version (read-only, no auth)
            resp2 = self._exchange(ip, num, smb2_negotiate_request())
        if not resp2:
            return ProbeResult(error="connection failed")

        port.service.name = "smb"
        # keep a richer product from nmap -sV ("Samba smbd", "Microsoft Windows
        # netbios-ssn"); only label it generically when nothing better is known
        set_service_version(port, "SMB", confidence=Confidence.MEDIUM)
        info: dict = {"reachable": True}
        findings = [Finding(
            title="SMB service reachable", asset=f"{ip}:{num}",
            evidence="TCP 445/139 accepts connections",
            description="An SMB/CIFS service is reachable on this host.",
            why_it_matters="SMB exposed to untrusted networks is a common "
                           "lateral-movement and ransomware vector.",
            severity=Severity.MEDIUM, confidence=Confidence.MEDIUM,
            impact="If reachable externally, high-risk exposure.",
            remediation="Restrict SMB to internal/trusted segments; never expose "
                        "to the internet.",
            validation=ValidationState.OBSERVED, source="smb-probe",
            category="exposure")]

        dialect = parse_smb2_dialect(resp2)
        if dialect is not None:
            ver = _SMB2_DIALECTS.get(dialect, f"SMB2 dialect 0x{dialect:04x}")
            dialect_ev = f"SMB2 NEGOTIATE -> {ver}"
            if port.service.product == "SMB":
                # no software version known: the negotiated dialect is the best
                # version we have (e.g. "3.1.1")
                set_service_version(port, version=ver.replace("SMB ", ""),
                                    evidence=dialect_ev, confidence=Confidence.HIGH)
            else:
                # nmap identified the software (e.g. Samba smbd 4.15.13) — keep
                # that version and record the dialect alongside as evidence
                if dialect_ev not in (port.service.evidence or ""):
                    port.service.evidence = "; ".join(
                        x for x in (port.service.evidence, dialect_ev) if x)
                set_service_version(port, confidence=Confidence.HIGH)
            info["dialect"] = ver

        # 2) does it also speak SMBv1? (separate connect; high-risk if yes)
        with self.scope.slot(ip, num) as s2:
            resp1 = self._exchange(ip, num, _SMB1_NEGOTIATE) if s2.allowed else b""
        smbv1 = len(resp1) >= 8 and resp1[4:8] == b"\xffSMB"
        info["smbv1"] = smbv1
        if smbv1:
            findings.append(Finding(
                title="SMBv1 (SMB1/CIFS) enabled", asset=f"{ip}:{num}",
                evidence="server answered an SMB1 NEGOTIATE (\\xffSMB)",
                description="The host still supports the legacy SMBv1 protocol.",
                why_it_matters="SMBv1 is deprecated and the vector for EternalBlue "
                               "(MS17-010) / WannaCry / NotPetya.",
                severity=Severity.HIGH, confidence=Confidence.HIGH,
                impact="Wormable RCE exposure if unpatched; credential-relay risk.",
                remediation="Disable SMBv1 entirely; require SMBv2/3 with signing.",
                validation=ValidationState.CONFIRMED, source="smb-probe",
                category="insecure-protocol"))
        return ProbeResult(data={"smb": info}, findings=findings)


def _mongo_listdb_query() -> bytes:
    """Legacy OP_QUERY for the admin command {listDatabases:1}. Unauthenticated
    reads succeed on open instances; auth-required ones return an error doc."""
    elem = b"\x10" + b"listDatabases" + b"\x00" + struct.pack("<i", 1)
    doc = struct.pack("<i", 4 + len(elem) + 1) + elem + b"\x00"
    body = (struct.pack("<i", 0) + b"admin.$cmd\x00" + struct.pack("<i", 0)
            + struct.pack("<i", -1) + doc)
    return struct.pack("<iiii", 16 + len(body), 1, 0, 2004) + body    # opCode OP_QUERY


class DatabaseProbe(ServiceProbe):
    name = "database"
    _DB_PORTS = {3306: "mysql", 5432: "postgresql", 6379: "redis",
                 27017: "mongodb", 1433: "mssql", 11211: "memcached",
                 9200: "elasticsearch", 5984: "couchdb"}

    def matches(self, port: Port) -> bool:
        return port.number in self._DB_PORTS or port.service.name in self._DB_PORTS.values()

    def probe(self, host: Host, port: Port) -> ProbeResult:
        product = self._DB_PORTS.get(port.number, port.service.name)
        findings = []
        info = {"product": product}

        # Redis: safe unauthenticated INFO check (read-only; detects open instance).
        if product == "redis":
            data, _ = _recv_banner(self.scope, self.config, host.ip, port.number,
                                   send=b"INFO server\r\n", read=1024)
            if data and b"redis_version" in data:
                info["unauthenticated"] = True
                ver = ""
                for line in data.decode("latin-1", "replace").splitlines():
                    if line.startswith("redis_version:"):
                        ver = line.split(":", 1)[1].strip()
                info["version"] = ver
                set_service_version(port, "Redis", ver, confidence=Confidence.HIGH)
                findings.append(Finding(
                    title="Unauthenticated Redis instance", asset=f"{host.ip}:{port.number}",
                    evidence=f"INFO returned server data (redis_version={ver})",
                    description="Redis responded to INFO without authentication.",
                    why_it_matters="Open Redis allows data theft and, often, remote code execution.",
                    severity=Severity.HIGH, confidence=Confidence.HIGH,
                    impact="Full read/write of cached data; potential RCE via known techniques.",
                    remediation="Enable requirepass/ACLs, bind to localhost, firewall the port.",
                    validation=ValidationState.CONFIRMED, source="database-probe", category="exposure",
                ))
            elif data and b"NOAUTH" in data:
                info["unauthenticated"] = False

        # MySQL/MariaDB send their version in cleartext in the initial handshake.
        elif product == "mysql":
            data, _ = _recv_banner(self.scope, self.config, host.ip, port.number,
                                   read=256)
            if data:
                mprod, mver = parse_mysql_greeting(data)
                if mver:
                    product = mprod
                    info["version"] = mver
                    # MariaDB prefixes a fake "5.5.5-" for old-client compat
                    clean = re.sub(r"^5\.5\.5-", "", mver)
                    clean = re.sub(r"-MariaDB.*$", "", clean, flags=re.I)
                    set_service_version(port, "MariaDB" if mprod == "mariadb"
                                        else "MySQL", clean,
                                        evidence=f"handshake greeting: {mver[:80]}",
                                        confidence=Confidence.HIGH)
            port.service.name = product
            findings.append(Finding(
                title=f"Database service exposed: {product}", asset=f"{host.ip}:{port.number}",
                evidence=f"open port {port.number}" + (f"; version {info.get('version')}"
                                                       if info.get("version") else ""),
                description=f"A {product} database service is listening.",
                why_it_matters="Database ports reachable from untrusted networks are high-value targets.",
                severity=Severity.MEDIUM, confidence=Confidence.MEDIUM,
                impact="Potential data exposure if authentication/network controls are weak.",
                remediation="Bind to internal interfaces, require strong auth, firewall the port. Do not expose publicly.",
                validation=ValidationState.OBSERVED, source="database-probe", category="exposure",
            ))
        # Deep, read-only, unauthenticated exposure checks (never credentials).
        elif product == "mongodb":
            findings.append(self._mongo_check(host, port, info))
        elif product == "memcached":
            findings.append(self._memcached_check(host, port, info))
        elif product == "elasticsearch":
            findings.append(self._http_db_check(
                host, port, info, "elasticsearch", "/_cat/indices?v",
                ("green", "yellow", "red", "health", "docs.count"), "index listing"))
        elif product == "couchdb":
            findings.append(self._http_db_check(
                host, port, info, "couchdb", "/_all_dbs",
                ("_users", "_replicator", "["), "database listing"))
        elif product in ("mssql", "postgresql"):
            port.service.name = product
            findings.append(self._exposure_finding(host, port, product))
        # NOTE: we deliberately never attempt credential guessing on databases.
        return ProbeResult(data={"database": info}, findings=findings)

    # -- deep per-product helpers (all read-only, no auth, no writes) ------ #
    def _exposure_finding(self, host, port, product, *, sev=Severity.MEDIUM,
                          val=ValidationState.OBSERVED) -> Finding:
        return Finding(
            title=f"Database service exposed: {product}",
            asset=f"{host.ip}:{port.number}", evidence=f"open port {port.number}",
            description=f"A {product} database service is listening.",
            why_it_matters="Database ports reachable from untrusted networks are "
                           "high-value targets.",
            severity=sev, confidence=Confidence.MEDIUM,
            impact="Potential data exposure if authentication/network controls "
                   "are weak.",
            remediation="Bind to internal interfaces, require strong auth, "
                        "firewall the port. Do not expose publicly.",
            validation=val, source="database-probe", category="exposure")

    def _unauth_finding(self, host, port, product, what, evidence) -> Finding:
        return Finding(
            title=f"Unauthenticated {product} instance",
            asset=f"{host.ip}:{port.number}", evidence=evidence,
            description=f"{product} returned {what} without authentication.",
            why_it_matters="An open datastore exposes (and often lets an attacker "
                           "modify) all stored data; several allow RCE.",
            severity=Severity.HIGH, confidence=Confidence.HIGH,
            impact="Full unauthenticated read (often write) of stored data.",
            remediation="Require authentication, bind to localhost/trusted nets, "
                        "and firewall the port.",
            validation=ValidationState.CONFIRMED, source="database-probe",
            category="exposure")

    def _mongo_check(self, host, port, info) -> Finding:
        port.service.name = "mongodb"
        data, _ = _recv_banner(self.scope, self.config, host.ip, port.number,
                               send=_mongo_listdb_query(), read=4096)
        if not data:
            return self._exposure_finding(host, port, "mongodb")
        low = data.lower()
        if b"databases" in low and not any(x in low for x in (
                b"requires auth", b"not authorized", b"unauthorized", b"errmsg")):
            info["unauthenticated"] = True
            return self._unauth_finding(host, port, "MongoDB", "a database listing",
                                        "OP_QUERY listDatabases returned a database "
                                        "list without authentication")
        info["unauthenticated"] = False
        return self._exposure_finding(host, port, "mongodb")  # present, auth required

    def _memcached_check(self, host, port, info) -> Finding:
        port.service.name = "memcached"
        data, _ = _recv_banner(self.scope, self.config, host.ip, port.number,
                               send=b"stats\r\n", read=2048)
        if data and b"STAT " in data:
            ver = ""
            for line in data.decode("latin-1", "replace").splitlines():
                if line.startswith("STAT version"):
                    ver = line.split(" ", 2)[-1].strip()
            info["unauthenticated"] = True
            info["version"] = ver
            if ver:
                set_service_version(port, "Memcached", ver,
                                    confidence=Confidence.HIGH)
            return self._unauth_finding(
                host, port, "Memcached", "server statistics",
                f"stats returned server data without auth"
                + (f" (version {ver})" if ver else ""))
        return self._exposure_finding(host, port, "memcached")

    def _http_db_check(self, host, port, info, product, path, markers, what
                       ) -> Finding:
        from ..webfetch import fetch
        port.service.name = product
        for scheme in ("http", "https"):
            st, _h, body = fetch(host.ip, port.number, scheme, path,
                                 timeout=self.config.timeout)
            if st is None:
                continue
            self._http_db_version(host, port, product, scheme)
            if st == 200 and any(m in body for m in markers):
                info["unauthenticated"] = True
                return self._unauth_finding(
                    host, port, product, f"a {what}",
                    f"GET {path} -> HTTP 200 exposing the {what} without auth")
            if st in (401, 403):
                info["unauthenticated"] = False
                return self._exposure_finding(host, port, product)
            break
        return self._exposure_finding(host, port, product)

    # ES root: {"version": {"number": "7.17.9", ...}}; CouchDB root:
    # {"couchdb": "Welcome", "version": "3.3.2", ...}
    _HTTP_DB_VER = {
        "elasticsearch": ("Elasticsearch",
                          re.compile(r'"number"\s*:\s*"(\d[\w.\-]*)"')),
        "couchdb": ("CouchDB", re.compile(r'"version"\s*:\s*"(\d[\w.\-]*)"')),
    }

    def _http_db_version(self, host, port, product, scheme) -> None:
        """One read-only GET / to record the server version (served without
        auth on default ES/CouchDB installs; silently skipped when not)."""
        spec = self._HTTP_DB_VER.get(product)
        if not spec or port.service.version:
            return
        from ..webfetch import fetch
        st, _h, body = fetch(host.ip, port.number, scheme, "/",
                             timeout=self.config.timeout)
        if st == 200 and body:
            m = spec[1].search(body)
            if m:
                set_service_version(port, spec[0], m.group(1),
                                    evidence=f"GET / -> {spec[0]} {m.group(1)}",
                                    confidence=Confidence.HIGH)


class GenericProbe(ServiceProbe):
    name = "generic"

    def matches(self, port: Port) -> bool:
        return True  # fallback

    def probe(self, host: Host, port: Port) -> ProbeResult:
        if port.service.banner:
            return ProbeResult(data={"generic": {"banner": port.service.banner}})
        data, err = _recv_banner(self.scope, self.config, host.ip, port.number,
                                 send=b"\r\n", read=256)
        if data:
            banner = data.decode("latin-1", "replace").strip()
            port.service.banner = banner
            if banner and port.service.confidence == Confidence.LOW:
                port.service.confidence = Confidence.MEDIUM
            # a recognisable product in an unknown-port banner -> record version
            prod, ver = banner_product_version(banner)
            if prod:
                set_service_version(port, prod, ver)
            return ProbeResult(data={"generic": {"banner": banner}})
        return ProbeResult(error=err or "no banner")

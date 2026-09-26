"""Additional safe service probes: SSH, SMTP, DNS, SMB, Database, Generic.

All are read-only banner/metadata probes. None attempt authentication, none
send credentials, none mutate remote state. Each re-checks scope before every
connection.
"""
from __future__ import annotations

import socket
import struct

from ..models import Confidence, Finding, Host, Port, Service, Severity, ValidationState
from .base import ProbeResult, ServiceProbe


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
            port.service.product = software
            port.service.confidence = Confidence.HIGH
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
        info = {"banner": text.splitlines()[0] if text else "",
                "capabilities": caps, "starttls": starttls}
        port.service.name = "smtp"
        port.service.confidence = Confidence.HIGH
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


class DNSProbe(ServiceProbe):
    name = "dns"

    def matches(self, port: Port) -> bool:
        return port.service.name == "dns" or port.number == 53

    def probe(self, host: Host, port: Port) -> ProbeResult:
        # Safe CH TXT version.bind query over TCP (read-only identification).
        query = self._build_version_query()
        framed = struct.pack("!H", len(query)) + query
        data, err = _recv_banner(self.scope, self.config, host.ip, port.number,
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
            port.service.product = version
            port.service.confidence = Confidence.HIGH
        port.service.name = "dns"
        return ProbeResult(data={"dns": info})

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


class SMBProbe(ServiceProbe):
    name = "smb"

    def matches(self, port: Port) -> bool:
        return port.service.name in ("smb", "netbios-ssn", "microsoft-ds") or \
            port.number in (139, 445)

    def probe(self, host: Host, port: Port) -> ProbeResult:
        # Presence-only identification. Deep SMB enumeration is delegated to
        # dedicated tools when authorized; here we just confirm the service.
        with self.scope.slot(host.ip, port.number) as s:
            if not s.allowed:
                return ProbeResult(error="scope denied")
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(self.config.timeout)
            try:
                sock.connect((host.ip, port.number))
                reachable = True
            except OSError as exc:
                return ProbeResult(error=str(exc))
            finally:
                try:
                    sock.close()
                except OSError:
                    pass
        port.service.name = "smb"
        port.service.confidence = Confidence.MEDIUM
        finding = Finding(
            title="SMB service reachable", asset=f"{host.ip}:{port.number}",
            evidence="TCP 445/139 accepts connections",
            description="An SMB/CIFS service is reachable on this host.",
            why_it_matters="SMB exposed to untrusted networks is a common lateral-movement and ransomware vector.",
            severity=Severity.MEDIUM, confidence=Confidence.MEDIUM,
            impact="If reachable externally, high-risk exposure.",
            remediation="Restrict SMB to internal/trusted segments; never expose to the internet.",
            validation=ValidationState.OBSERVED, source="smb-probe", category="exposure",
        )
        return ProbeResult(data={"smb": {"reachable": reachable}}, findings=[finding])


class DatabaseProbe(ServiceProbe):
    name = "database"
    _DB_PORTS = {3306: "mysql", 5432: "postgresql", 6379: "redis",
                 27017: "mongodb", 1433: "mssql", 11211: "memcached",
                 9200: "elasticsearch"}

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
                port.service.product = ver
                port.service.confidence = Confidence.HIGH
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

        # Elasticsearch: safe GET / (delegated to HTTP probe usually) — mark exposure.
        elif product in ("mongodb", "mssql", "postgresql", "mysql", "memcached"):
            port.service.name = product
            findings.append(Finding(
                title=f"Database service exposed: {product}", asset=f"{host.ip}:{port.number}",
                evidence=f"open port {port.number}",
                description=f"A {product} database service is listening.",
                why_it_matters="Database ports reachable from untrusted networks are high-value targets.",
                severity=Severity.MEDIUM, confidence=Confidence.MEDIUM,
                impact="Potential data exposure if authentication/network controls are weak.",
                remediation="Bind to internal interfaces, require strong auth, firewall the port. Do not expose publicly.",
                validation=ValidationState.OBSERVED, source="database-probe", category="exposure",
            ))
        # NOTE: we deliberately never attempt credential guessing on databases.
        return ProbeResult(data={"database": info}, findings=findings)


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
            return ProbeResult(data={"generic": {"banner": banner}})
        return ProbeResult(error=err or "no banner")

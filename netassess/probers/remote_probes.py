"""Remote-access service probes: RDP, VNC, rsync (read-only).

Non-destructive presence + security-posture checks:

  * **RDP (3389)** — sends only the X.224/RDP negotiation and reads which
    security protocol the server selects, to determine whether Network Level
    Authentication (NLA) is enforced. No login attempt.
  * **VNC (5900-5906)** — reads the RFB version and the *offered* security types
    (flags "None"/unauthenticated access). No auth, no framebuffer access.
  * **rsync (873)** — reads the daemon greeting and lists exposed modules
    (anonymous module listing, like a share list). No file transfer.

Each is scope-gated and connects once, read-only.
"""
from __future__ import annotations

import socket
import struct

from ..models import Confidence, Finding, Host, Port, Service, Severity, ValidationState
from .base import ProbeResult, ServiceProbe


# --------------------------------------------------------------------------- #
# RDP
# --------------------------------------------------------------------------- #
def build_rdp_neg_request(requested_protocols: int = 0) -> bytes:
    # RDP_NEG_REQ: type=1, flags=0, length=8, requestedProtocols (LE)
    neg = struct.pack("<BBHI", 0x01, 0x00, 0x0008, requested_protocols)
    # X.224 Connection Request
    li = 6 + len(neg)
    x224 = struct.pack("!BBHHB", li, 0xE0, 0x0000, 0x0000, 0x00) + neg
    tpkt = struct.pack("!BBH", 0x03, 0x00, 4 + len(x224)) + x224
    return tpkt


def parse_rdp_neg_response(data: bytes) -> dict | None:
    """Parse the X.224 CC + RDP negotiation response."""
    if len(data) < 11 or data[0] != 0x03:
        return None
    # negotiation structure begins after TPKT(4) + X.224 CC header(7)
    body = data[11:]
    if len(body) < 8:
        # server accepted with a bare CC and no negotiation response
        return {"type": "cc-only"}
    ntype = body[0]
    code = struct.unpack("<I", body[4:8])[0]
    if ntype == 0x02:
        return {"type": "rsp", "selected_protocol": code}
    if ntype == 0x03:
        return {"type": "failure", "failure_code": code}
    return {"type": "unknown"}


_RDP_PROTO = {0: "Standard RDP Security", 1: "TLS", 2: "CredSSP/NLA",
              8: "RDSTLS", 11: "CredSSP+EarlyUser"}
_HYBRID_REQUIRED = 0x00000005  # HYBRID_REQUIRED_BY_SERVER (NLA enforced)


class RDPProbe(ServiceProbe):
    name = "rdp"

    def matches(self, port: Port) -> bool:
        return port.number == 3389 or port.service.name in ("rdp", "ms-wbt-server")

    def probe(self, host: Host, port: Port) -> ProbeResult:
        ip, num = host.ip, port.number
        if not self.in_scope(ip, num):
            return ProbeResult(error="scope denied")
        # request RDP-only (0) so a success means NLA is NOT required
        with self.scope.slot(ip, num) as s:
            if not s.allowed:
                return ProbeResult(error="scope denied")
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(self.config.timeout)
            try:
                sock.connect((ip, num))
                sock.sendall(build_rdp_neg_request(0))
                data = sock.recv(512)
            except OSError as exc:
                return ProbeResult(error=str(exc))
            finally:
                try:
                    sock.close()
                except OSError:
                    pass

        port.service.name = "rdp"
        port.service.confidence = Confidence.HIGH
        resp = parse_rdp_neg_response(data)
        findings = [Finding(
            title="RDP service exposed", asset=f"{ip}:{num}",
            evidence="RDP negotiation responded",
            description="A Remote Desktop (RDP) service is reachable.",
            why_it_matters="RDP is a frequent brute-force, credential-stuffing and "
                           "ransomware entry point; exposure to untrusted networks is high-risk.",
            severity=Severity.MEDIUM, confidence=Confidence.HIGH,
            remediation="Restrict RDP to VPN/trusted networks; enforce NLA and MFA.",
            validation=ValidationState.OBSERVED, source="rdp-probe", category="exposure",
        )]
        info = {"negotiation": resp}
        if resp and resp.get("type") in ("rsp", "cc-only"):
            sel = resp.get("selected_protocol", 0)
            info["selected_protocol"] = _RDP_PROTO.get(sel, str(sel))
            if sel in (0,) or resp.get("type") == "cc-only":
                findings.append(Finding(
                    title="RDP allows connections without Network Level Authentication",
                    asset=f"{ip}:{num}",
                    evidence=f"server accepted RDP-only negotiation "
                             f"(selected: {_RDP_PROTO.get(sel, sel)})",
                    description="The RDP server does not require NLA (it accepted a "
                                "Standard RDP Security negotiation).",
                    why_it_matters="Without NLA, RDP exposes the pre-auth attack "
                                   "surface (a class that included BlueKeep) and is "
                                   "susceptible to MITM.",
                    severity=Severity.HIGH, confidence=Confidence.HIGH,
                    impact="Larger pre-authentication attack surface; MITM risk.",
                    remediation="Require Network Level Authentication (CredSSP) on the RDP host.",
                    validation=ValidationState.CONFIRMED, source="rdp-probe", category="config",
                ))
        elif resp and resp.get("type") == "failure":
            info["failure_code"] = resp["failure_code"]
            if resp["failure_code"] == _HYBRID_REQUIRED:
                host.notes.append("RDP enforces NLA (HYBRID_REQUIRED_BY_SERVER)")
        return ProbeResult(data={"rdp": info}, findings=findings)


# --------------------------------------------------------------------------- #
# VNC
# --------------------------------------------------------------------------- #
_VNC_SECTYPES = {0: "Invalid", 1: "None", 2: "VNC Auth", 16: "Tight",
                 18: "TLS", 19: "VeNCrypt", 30: "Apple ARD"}


def parse_vnc_sectypes(version_minor: int, data: bytes) -> list[int]:
    """Return offered security-type numbers from the server response."""
    if not data:
        return []
    if version_minor >= 7:
        n = data[0]
        return list(data[1:1 + n]) if n else []
    # RFB 3.3: server sends a single 4-byte security type
    if len(data) >= 4:
        return [struct.unpack("!I", data[:4])[0]]
    return []


class VNCProbe(ServiceProbe):
    name = "vnc"

    def matches(self, port: Port) -> bool:
        return port.service.name == "vnc" or 5900 <= port.number <= 5906

    def probe(self, host: Host, port: Port) -> ProbeResult:
        ip, num = host.ip, port.number
        if not self.in_scope(ip, num):
            return ProbeResult(error="scope denied")
        with self.scope.slot(ip, num) as s:
            if not s.allowed:
                return ProbeResult(error="scope denied")
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(self.config.timeout)
            try:
                sock.connect((ip, num))
                banner = sock.recv(12)
                if not banner.startswith(b"RFB "):
                    return ProbeResult(error="not RFB/VNC")
                version = banner[4:11].decode("latin-1", "replace")
                minor = int(version.split(".")[1]) if "." in version else 3
                # complete version handshake to learn offered security types
                sock.sendall(banner)
                sectypes = parse_vnc_sectypes(minor, sock.recv(64))
            except (OSError, ValueError) as exc:
                return ProbeResult(error=str(exc))
            finally:
                try:
                    sock.close()
                except OSError:
                    pass

        port.service.name = "vnc"
        port.service.product = f"RFB {version}"
        port.service.confidence = Confidence.HIGH
        offered = [_VNC_SECTYPES.get(t, str(t)) for t in sectypes]
        findings = []
        if 1 in sectypes:  # None
            findings.append(Finding(
                title="VNC offers 'None' authentication (unauthenticated access)",
                asset=f"{ip}:{num}",
                evidence=f"RFB {version}; security types offered: {offered}",
                description="The VNC server offers the 'None' security type, allowing "
                            "screen/keyboard access without any authentication.",
                why_it_matters="Anyone who can reach the port gets full interactive "
                               "control of the desktop.",
                severity=Severity.CRITICAL, confidence=Confidence.HIGH,
                impact="Unauthenticated remote desktop control.",
                remediation="Require VNC authentication (or tunnel over VPN/SSH); "
                            "never expose 'None' auth.",
                validation=ValidationState.CONFIRMED, source="vnc-probe", category="exposure",
            ))
        else:
            findings.append(Finding(
                title="VNC service exposed", asset=f"{ip}:{num}",
                evidence=f"RFB {version}; security types: {offered or 'unknown'}",
                description="A VNC (remote desktop) service is reachable.",
                why_it_matters="VNC often uses weak (DES-based) auth and is a remote-"
                               "access exposure.",
                severity=Severity.MEDIUM, confidence=Confidence.HIGH,
                remediation="Restrict to VPN/trusted networks; use strong auth.",
                validation=ValidationState.OBSERVED, source="vnc-probe", category="exposure",
            ))
        return ProbeResult(data={"vnc": {"version": version, "security_types": offered}},
                           findings=findings)


# --------------------------------------------------------------------------- #
# rsync
# --------------------------------------------------------------------------- #
def parse_rsync_modules(text: str) -> list[str]:
    modules = []
    for line in text.splitlines():
        line = line.strip()
        if not line or line.startswith("@RSYNCD"):
            continue
        # "module <tab/spaces> comment"
        modules.append(line.split("\t")[0].split("  ")[0].strip())
    return [m for m in modules if m]


class RsyncProbe(ServiceProbe):
    name = "rsync"

    def matches(self, port: Port) -> bool:
        return port.number == 873 or port.service.name == "rsync"

    def probe(self, host: Host, port: Port) -> ProbeResult:
        ip, num = host.ip, port.number
        if not self.in_scope(ip, num):
            return ProbeResult(error="scope denied")
        with self.scope.slot(ip, num) as s:
            if not s.allowed:
                return ProbeResult(error="scope denied")
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(self.config.timeout)
            try:
                sock.connect((ip, num))
                greeting = sock.recv(64)
                if not greeting.startswith(b"@RSYNCD:"):
                    return ProbeResult(error="not rsync")
                version = greeting.decode("latin-1", "replace").strip()
                # echo greeting, then request module list
                sock.sendall(greeting.split(b"\n")[0] + b"\n")
                sock.sendall(b"\n")  # empty module name -> list modules
                listing = b""
                try:
                    while len(listing) < 8192:
                        chunk = sock.recv(2048)
                        if not chunk:
                            break
                        listing += chunk
                        if b"@RSYNCD: EXIT" in listing:
                            break
                except socket.timeout:
                    pass
            except OSError as exc:
                return ProbeResult(error=str(exc))
            finally:
                try:
                    sock.close()
                except OSError:
                    pass

        port.service.name = "rsync"
        port.service.product = version
        port.service.confidence = Confidence.HIGH
        modules = parse_rsync_modules(listing.decode("latin-1", "replace"))
        findings = []
        if modules:
            findings.append(Finding(
                title="rsync daemon exposes module list", asset=f"{ip}:{num}",
                evidence=f"modules: {', '.join(modules[:10])}"
                         + (" …" if len(modules) > 10 else ""),
                description="An rsync daemon is reachable and anonymously lists its "
                            "modules (shares).",
                why_it_matters="Exposed rsync modules may allow unauthenticated read "
                               "(or write) of files/backups; module names reveal "
                               "sensitive paths.",
                severity=Severity.MEDIUM, confidence=Confidence.HIGH,
                impact="Potential unauthenticated file access / data disclosure.",
                remediation="Require auth on rsync modules, set 'list = no', and "
                            "restrict the daemon to trusted networks.",
                validation=ValidationState.OBSERVED, source="rsync-probe", category="exposure",
            ))
        else:
            findings.append(Finding(
                title="rsync daemon reachable", asset=f"{ip}:{num}",
                evidence=version, description="An rsync daemon is reachable.",
                why_it_matters="rsync exposed to untrusted networks can disclose or "
                               "modify files depending on configuration.",
                severity=Severity.LOW, confidence=Confidence.HIGH,
                remediation="Restrict rsync to trusted networks; require authentication.",
                validation=ValidationState.OBSERVED, source="rsync-probe", category="exposure",
            ))
        return ProbeResult(data={"rsync": {"version": version, "modules": modules}},
                           findings=findings)

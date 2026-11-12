"""SMB null-session / share enumeration via external tools.

Correctly enumerating SMB shares requires an anonymous SESSION_SETUP followed by
a DCERPC NetrShareEnum over a named pipe — fragile to hand-roll and signing-
sensitive. So we shell out to the tools pentesters already use: `smbclient -N`
(null session) or nmap's `smb-enum-shares` script, whichever is installed, and
normalise the result. Strictly read-only: list shares, never write or mount.

If neither tool is present the stage is skipped (the pure-Python SMB version /
SMBv1 detection in SMBProbe still runs).
"""
from __future__ import annotations

import re
import xml.etree.ElementTree as ET

from ..models import Confidence, Finding, Severity, ValidationState
from .base import ToolAdapter
from .process import run, which

# default administrative shares — noteworthy but less interesting than custom ones
_ADMIN_SHARES = {"ADMIN$", "IPC$", "C$", "D$", "PRINT$", "FAX$"}


class SmbEnumAdapter(ToolAdapter):
    name = "smb-enum"

    def available(self) -> bool:
        return which("smbclient") is not None or which("nmap") is not None

    # -- tool invocation -------------------------------------------------- #
    def enumerate_host(self, ip: str, *, timeout: int = 20) -> dict:
        if which("smbclient"):
            res = run(["smbclient", "-N", "-g", "-L", f"//{ip}",
                       "-t", str(int(timeout))], timeout=timeout + 5)
            return self.parse_smbclient(f"{res.stdout}\n{res.stderr}")
        if which("nmap"):
            res = run(["nmap", "-Pn", "-p445", "--script", "smb-enum-shares",
                       "-oX", "-", ip], timeout=timeout + 40)
            return self.parse_nmap(res.stdout)
        return {}

    # -- parsers (unit-testable) ------------------------------------------ #
    def parse_smbclient(self, out: str) -> dict:
        """smbclient -g -L emits 'Disk|name|comment' lines; an access-denied
        anonymous bind means null sessions are refused."""
        shares, denied = [], False
        for line in out.splitlines():
            line = line.strip()
            if any(x in line for x in ("NT_STATUS_ACCESS_DENIED",
                                       "NT_STATUS_LOGON_FAILURE",
                                       "NT_STATUS_ACCOUNT_DISABLED")):
                denied = True
            parts = line.split("|")
            if len(parts) >= 2 and parts[0] in ("Disk", "IPC", "Printer"):
                shares.append({"name": parts[1],
                               "type": parts[0],
                               "comment": parts[2] if len(parts) > 2 else ""})
        return {"null_session": bool(shares) and not denied,
                "shares": shares, "denied": denied}

    def parse_nmap(self, xml_text: str) -> dict:
        shares = []
        anon = False
        try:
            root = ET.fromstring(xml_text)
        except ET.ParseError:
            return {}
        for sc in root.iter("script"):
            if sc.get("id") != "smb-enum-shares":
                continue
            out = sc.get("output") or ""
            # each share is a "\\ip\NAME:" block; access lines mention Anonymous
            for m in re.finditer(r"\\\\[^\\]+\\([^\s:]+):", out):
                name = m.group(1)
                shares.append({"name": name,
                               "type": "Disk", "comment": ""})
            if re.search(r"Anonymous access:\s*READ", out, re.I):
                anon = True
            # structured elems too
            for tbl in sc.iter("table"):
                key = tbl.get("key") or ""
                mm = re.match(r"\\\\[^\\]+\\(.+)", key)
                if mm and not any(s["name"] == mm.group(1) for s in shares):
                    shares.append({"name": mm.group(1), "type": "Disk",
                                   "comment": ""})
        return {"null_session": anon or bool(shares), "shares": shares,
                "denied": False}

    # -- findings --------------------------------------------------------- #
    def to_findings(self, ip: str, port: int, result: dict) -> list[Finding]:
        if not result:
            return []
        shares = result.get("shares") or []
        asset = f"{ip}:{port}"
        out: list[Finding] = []
        if result.get("null_session") and shares:
            names = ", ".join(s["name"] for s in shares[:25])
            custom = [s["name"] for s in shares
                      if s["name"].upper() not in _ADMIN_SHARES]
            sev = Severity.HIGH if custom else Severity.MEDIUM
            out.append(Finding(
                title="SMB null session allowed (anonymous share enumeration)",
                asset=asset,
                evidence=f"anonymous listing returned {len(shares)} share(s): "
                         f"{names}" + (f"; non-default: {', '.join(custom[:10])}"
                                       if custom else ""),
                description="The host allowed an unauthenticated (null) SMB "
                            "session and disclosed its share list.",
                why_it_matters="Null sessions leak shares, users and policy, and "
                               "non-default shares may expose readable data.",
                severity=sev, confidence=Confidence.HIGH,
                impact="Information disclosure; readable shares may expose data.",
                remediation="Disable null/anonymous SMB sessions (RestrictAnonymous"
                            "/RestrictNullSessAccess); restrict share permissions.",
                validation=ValidationState.CONFIRMED,
                source="smb-enum", category="exposure"))
        elif result.get("denied"):
            out.append(Finding(
                title="SMB present; null session denied",
                asset=asset, evidence="anonymous bind refused (ACCESS_DENIED)",
                description="SMB is reachable but rejected an anonymous session.",
                why_it_matters="Good — anonymous enumeration is blocked; the "
                               "service is still exposed.",
                severity=Severity.LOW, confidence=Confidence.MEDIUM,
                impact="Limited; confirm network exposure is intended.",
                remediation="Keep null sessions disabled; restrict SMB to trusted "
                            "networks.",
                validation=ValidationState.OBSERVED,
                source="smb-enum", category="exposure"))
        return out

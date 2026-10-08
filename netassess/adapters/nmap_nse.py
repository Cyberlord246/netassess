"""Optional nmap NSE vulnerability adapter.

Runs nmap's version-to-CVE scripts against the already-discovered open ports and
normalises the results into netassess Findings (CVE id in the title, so the
end-of-run de-dup and KEV/EPSS enrichment apply). This is an *additional* CVE
source alongside the offline KB — opt-in, and only invoked on in-scope targets.

Default script is ``vulners`` (a read-only version->CVE lookup; it queries
vulners.com, so it needs internet and the script installed). The ``vuln``
category is broader and bundled with nmap but can be more active, so it is
opt-in via ``--nmap-vuln-script vuln``.
"""
from __future__ import annotations

import re
import xml.etree.ElementTree as ET

from ..models import Confidence, Finding, Severity, ValidationState
from .base import ToolAdapter
from .process import ProcResult, run, which

_CVE_CVSS = re.compile(r"(CVE-\d{4}-\d{4,7})[\s|]+([0-9]+(?:\.[0-9]+)?)")
_CVE = re.compile(r"CVE-\d{4}-\d{4,7}")


def _sev_from_cvss(cvss: float) -> Severity:
    if cvss >= 9.0:
        return Severity.CRITICAL
    if cvss >= 7.0:
        return Severity.HIGH
    if cvss >= 4.0:
        return Severity.MEDIUM
    return Severity.LOW


class NmapNSEAdapter(ToolAdapter):
    name = "nmap-nse"

    def available(self) -> bool:
        return which("nmap") is not None

    def build_argv(self, targets_file: str, ports: str, *,
                   script: str = "vulners") -> list[str]:
        argv = ["nmap", "-sV", "--script", script, "-oX", "-", "--open"]
        if ports:
            argv += ["-p", ports]
        argv += ["-iL", targets_file]
        return argv

    def parse_xml(self, xml_text: str) -> list[dict]:
        """Return [{ip, port, cve, cvss}] from nmap XML NSE script output."""
        out: list[dict] = []
        try:
            root = ET.fromstring(xml_text)
        except ET.ParseError:
            return out
        for host in root.findall("host"):
            ip = ""
            for a in host.findall("address"):
                if a.get("addrtype") in ("ipv4", "ipv6"):
                    ip = a.get("addr", "")
                    break
            if not ip:
                continue
            # host-level and port-level scripts both possible
            scripts = host.findall("./hostscript/script")
            for port in host.findall("./ports/port"):
                pnum = port.get("portid")
                for sc in port.findall("script"):
                    out += self._from_script(ip, pnum, sc)
            for sc in scripts:
                out += self._from_script(ip, "", sc)
        return out

    def _from_script(self, ip: str, port: str, sc) -> list[dict]:
        text = sc.get("output") or ""
        found: dict[str, float] = {}
        # structured tables: each inner <table> holds <elem key="id">CVE..</elem>
        # and a sibling <elem key="cvss">7.5</elem> — pair them.
        for tbl in sc.iter("table"):
            cve = cvss = None
            for elem in tbl.findall("elem"):
                k, v = elem.get("key"), (elem.text or "").strip()
                if k == "id" and _CVE.fullmatch(v):
                    cve = v
                elif k == "cvss":
                    try:
                        cvss = float(v)
                    except ValueError:
                        pass
            if cve:
                found[cve] = max(found.get(cve, 0.0), cvss or 0.0)
        # text fallback: "CVE-2021-1234   7.5"
        for m in _CVE_CVSS.finditer(text):
            try:
                found[m.group(1)] = max(found.get(m.group(1), 0.0), float(m.group(2)))
            except ValueError:
                pass
        for m in _CVE.finditer(text):
            found.setdefault(m.group(0), 0.0)
        return [{"ip": ip, "port": port, "cve": cve, "cvss": cvss}
                for cve, cvss in found.items()]

    def to_findings(self, rows: list[dict]) -> list[Finding]:
        out = []
        for r in rows:
            asset = f"{r['ip']}:{r['port']}" if r.get("port") else r["ip"]
            cvss = r.get("cvss") or 0.0
            sev = _sev_from_cvss(cvss) if cvss else Severity.MEDIUM
            out.append(Finding(
                title=f"{r['cve']}: reported by nmap NSE",
                asset=asset,
                evidence=f"nmap NSE flagged {r['cve']}"
                         + (f" (CVSS {cvss})" if cvss else ""),
                description="nmap's vulnerability scripts correlated this service "
                            "version with a known CVE.",
                why_it_matters="Known-vulnerable version exposed.",
                severity=sev, confidence=Confidence.MEDIUM,
                impact=f"See {r['cve']}.",
                remediation="Confirm the version is affected (back-ports/config "
                            "may differ) and patch/upgrade.",
                validation=ValidationState.NEEDS_VALIDATION,
                source="nmap-nse", category="known-vulnerability",
            ))
        return out

    def scan(self, targets_file: str, ports: str, *, script: str = "vulners",
             run_timeout: float = 600.0) -> tuple[list[Finding], ProcResult]:
        argv = self.build_argv(targets_file, ports, script=script)
        res = run(argv, timeout=run_timeout)
        if res.not_found:
            return [], res
        rows = self.parse_xml(res.stdout) if res.stdout else []
        return self.to_findings(rows), res

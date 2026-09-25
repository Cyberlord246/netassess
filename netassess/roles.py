"""Asset-role classification + role-based anomaly detection.

Pure analysis over the asset graph — no network, no external data. Infers each
host's role(s) from its open services, then flags configurations that don't fit
the role: a database co-located with a public web app, an over-consolidated host
running several critical roles, an exposed management/orchestration plane, a
Domain Controller also serving unrelated apps, etc.

Unexpected exposure is often more telling than any single CVE — this turns the
raw port list into "what is this host, and what shouldn't be here?".
"""
from __future__ import annotations

from dataclasses import dataclass, field

from .models import Confidence, Finding, Host, Severity, ValidationState

# role -> indicative ports (TCP unless noted). Overlaps are fine; scoring sorts.
ROLE_PORTS: dict[str, set[int]] = {
    "web-server": {80, 443, 8080, 8443, 8000, 8888, 8081, 8082, 3000},
    "database": {3306, 5432, 1433, 1521, 27017, 6379, 11211, 9200, 9042, 5984},
    "mail-server": {25, 465, 587, 143, 993, 110, 995},
    "dns-server": {53},
    "file-server": {445, 139, 2049, 21, 873},
    "remote-access": {22, 23, 3389, 5900, 5901, 5902, 5903, 5985, 5986},
    "directory": {389, 636, 3268, 3269},
    "mgmt-plane": {2375, 2376, 6443, 10250, 623, 902, 5480, 9389},
    "monitoring": {5601, 9090, 9093, 8086, 9300},
}

# roles considered "critical" for consolidation analysis
_CRITICAL = {"web-server", "database", "mail-server", "file-server",
             "directory", "domain-controller"}
_DB_NAMES = {"mysql", "postgresql", "postgres", "mssql", "oracle", "mongodb",
             "redis", "memcached", "elasticsearch"}


@dataclass
class RoleResult:
    primary: str = "unknown"
    roles: list[str] = field(default_factory=list)
    scores: dict[str, int] = field(default_factory=dict)
    ports: set[int] = field(default_factory=set)


def classify(host: Host) -> RoleResult:
    ports = {p.number for p in host.open_ports()}
    ports |= {n for n, p in host.udp_ports.items()
              if p.state.value in ("open", "open|filtered")}
    names = {p.service.name for p in host.open_ports()}
    if not ports:
        return RoleResult()

    scores: dict[str, int] = {}
    for role, sig in ROLE_PORTS.items():
        hits = ports & sig
        if hits:
            scores[role] = len(hits)

    # Domain Controller = directory + Kerberos (88) [+ SMB]; supersedes 'directory'
    if 88 in ports and (389 in ports or "kerberos" in names or "ldap" in names):
        dc = scores.pop("directory", 0) + 2 + (1 if 445 in ports else 0)
        scores["domain-controller"] = dc

    roles = sorted(scores, key=lambda r: scores[r], reverse=True)
    primary = roles[0] if roles else "unknown"
    return RoleResult(primary=primary, roles=roles, scores=scores, ports=ports)


def _dbs_present(host: Host) -> list[str]:
    out = []
    for p in host.open_ports():
        if p.number in ROLE_PORTS["database"] or p.service.name in _DB_NAMES:
            out.append(f"{p.service.name}/{p.number}")
    return out


def detect_anomalies(host: Host, rr: RoleResult) -> list[Finding]:
    roles = set(rr.roles)
    ip = host.ip
    findings: list[Finding] = []

    # A) database co-located with a public web service
    if "web-server" in roles and "database" in roles:
        dbs = _dbs_present(host)
        findings.append(Finding(
            title="Database co-located with web service", asset=ip,
            evidence=f"web + database roles on one host; databases: {', '.join(dbs)}",
            description="This host serves web content and also exposes a database "
                        "service on a reachable port.",
            why_it_matters="Databases should sit behind the app tier, not be reachable "
                           "alongside it; a web-app compromise then reaches the DB "
                           "directly, and the DB port may be exposed beyond intent.",
            severity=Severity.MEDIUM, confidence=Confidence.MEDIUM,
            impact="Flat architecture — larger blast radius if the web app is breached.",
            remediation="Move the database to an internal segment; bind it to the app "
                        "host only; never expose DB ports to untrusted networks.",
            validation=ValidationState.OBSERVED, source="role-anomaly",
            category="architecture",
        ))

    # B) over-consolidation of critical roles on a single host
    crit = roles & _CRITICAL
    if len(crit) >= 3:
        findings.append(Finding(
            title="Multiple critical roles consolidated on one host", asset=ip,
            evidence="roles: " + ", ".join(sorted(crit)),
            description="A single host performs several critical roles at once.",
            why_it_matters="Consolidation makes the host a single point of failure and "
                           "a high-value target — one compromise affects many services.",
            severity=Severity.MEDIUM, confidence=Confidence.MEDIUM,
            impact="Concentrated blast radius; harder to segment and patch safely.",
            remediation="Separate critical roles onto dedicated hosts where feasible.",
            validation=ValidationState.OBSERVED, source="role-anomaly",
            category="architecture",
        ))

    # C) exposed management / orchestration plane
    if "mgmt-plane" in roles:
        mgmt = [f"{p.service.name}/{p.number}" for p in host.open_ports()
                if p.number in ROLE_PORTS["mgmt-plane"]]
        findings.append(Finding(
            title="Infrastructure management interface reachable", asset=ip,
            evidence="services: " + ", ".join(mgmt),
            description="A management/orchestration service (e.g. Docker API, "
                        "Kubernetes, IPMI, hypervisor) is reachable.",
            why_it_matters="Management planes often grant host- or cluster-level "
                           "control; unauthenticated exposure (e.g. Docker API) can "
                           "mean full takeover.",
            severity=Severity.HIGH, confidence=Confidence.MEDIUM,
            impact="Potential host/cluster compromise if the interface is weakly "
                   "authenticated.",
            remediation="Never expose management planes to untrusted networks; require "
                        "strong auth + mTLS; restrict by ACL/VPN.",
            validation=ValidationState.OBSERVED, source="role-anomaly",
            category="exposure",
        ))

    # D) Domain Controller also serving unrelated roles
    if "domain-controller" in roles:
        extra = roles - {"domain-controller", "dns-server", "file-server", "directory"}
        if extra:
            findings.append(Finding(
                title="Domain Controller running non-DC services", asset=ip,
                evidence="extra roles: " + ", ".join(sorted(extra)),
                description="This Domain Controller also exposes services beyond core "
                            "AD roles.",
                why_it_matters="DCs should be minimal and tightly controlled; extra "
                               "services enlarge the attack surface of the most "
                               "sensitive host in the domain.",
                severity=Severity.MEDIUM, confidence=Confidence.MEDIUM,
                impact="Increased attack surface on identity infrastructure.",
                remediation="Remove non-DC roles from Domain Controllers.",
                validation=ValidationState.OBSERVED, source="role-anomaly",
                category="architecture",
            ))

    # E) interactive remote access exposed alongside a public web app
    if "web-server" in roles and "remote-access" in roles:
        ra = [f"{p.service.name}/{p.number}" for p in host.open_ports()
              if p.number in {23, 3389, 5900, 5901, 5902, 5903}]
        if ra:
            findings.append(Finding(
                title="Interactive remote access exposed on a web host", asset=ip,
                evidence="remote-access services: " + ", ".join(ra),
                description="A host serving web content also exposes interactive "
                            "remote access (RDP/VNC/Telnet).",
                why_it_matters="Interactive access on an internet-facing app server is "
                               "a prime foothold target and should not share the edge.",
                severity=Severity.MEDIUM, confidence=Confidence.LOW,
                remediation="Restrict remote access to VPN/management networks; keep it "
                            "off internet-facing app hosts.",
                validation=ValidationState.OBSERVED, source="role-anomaly",
                category="exposure",
            ))
    return findings

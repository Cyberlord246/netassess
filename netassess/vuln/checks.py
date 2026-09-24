"""Safe, non-destructive vulnerability heuristics.

These checks derive findings from evidence already collected in the asset graph
(open ports, service versions, TLS metadata, HTTP headers). They perform NO new
network activity, NO exploitation, and NO credential attacks. Anything derived
from a version number is marked NEEDS_VALIDATION — a banner is not proof.

External scanner integrations (see ../adapters) are normalised into the same
Finding schema and merged alongside these checks.
"""
from __future__ import annotations

import re

from ..models import (
    Confidence, Finding, Host, Port, Severity, ValidationState,
)

# Services that are sensitive if reachable from untrusted networks.
_SENSITIVE_SERVICES = {
    "telnet": (Severity.HIGH, "Cleartext remote administration protocol."),
    "ftp": (Severity.MEDIUM, "Often cleartext; anonymous access common."),
    "rdp": (Severity.MEDIUM, "Remote Desktop is a frequent brute-force/ransomware entry point."),
    "vnc": (Severity.MEDIUM, "Remote framebuffer access; weak auth common."),
    "smb": (Severity.MEDIUM, "File sharing; lateral-movement vector."),
    "microsoft-ds": (Severity.MEDIUM, "SMB file sharing."),
    "msrpc": (Severity.LOW, "RPC endpoint mapper exposure."),
    "snmp": (Severity.MEDIUM, "Often default community strings; info disclosure."),
    "docker": (Severity.HIGH, "Unauthenticated Docker API = host takeover."),
    "memcached": (Severity.MEDIUM, "Unauthenticated cache; UDP amplification risk."),
    "elasticsearch": (Severity.MEDIUM, "Often unauthenticated data store."),
    "kibana": (Severity.MEDIUM, "Data-exploration UI; often unauthenticated."),
}

# Minimal, conservative EOL/known-weak version hints (evidence-gated).
# Format: service -> list of (regex, note, severity)
_VERSION_HINTS = {
    "openssh": [
        (re.compile(r"OpenSSH_([0-6]\.|7\.[0-3])", re.I),
         "OpenSSH version predates 7.4; several CVEs fixed in later releases.",
         Severity.LOW),
    ],
    "nginx": [
        (re.compile(r"nginx/1\.(1[0-9]|[0-9])\.", re.I),
         "nginx branch < 1.20; verify against current security advisories.",
         Severity.LOW),
    ],
    "apache": [
        (re.compile(r"Apache/2\.(2\.|4\.[0-9]$|4\.[1-4][0-9]$)", re.I),
         "Apache httpd 2.4.x below current; review CVE list for the exact build.",
         Severity.LOW),
    ],
}


def check_sensitive_exposure(host: Host, port: Port) -> list[Finding]:
    name = port.service.name.lower()
    if name not in _SENSITIVE_SERVICES:
        return []
    sev, why = _SENSITIVE_SERVICES[name]
    return [Finding(
        title=f"Sensitive service exposed: {name}",
        asset=f"{host.ip}:{port.number}",
        evidence=f"open {port.number}/tcp identified as {name}",
        description=f"A {name} service is listening on {host.ip}:{port.number}.",
        why_it_matters=why,
        severity=sev, confidence=port.service.confidence,
        impact="Elevated risk if reachable from untrusted networks.",
        remediation=f"Restrict {name} to trusted segments; disable if unused; enforce strong auth.",
        validation=ValidationState.OBSERVED, source="vuln-heuristic", category="exposure",
    )]


def check_version_hints(host: Host, port: Port) -> list[Finding]:
    svc = port.service
    text = f"{svc.product} {svc.version} {svc.banner}".strip()
    if not text:
        return []
    out = []
    for _key, rules in _VERSION_HINTS.items():
        for pattern, note, sev in rules:
            m = pattern.search(text)
            if m:
                out.append(Finding(
                    title=f"Potentially outdated software: {svc.name}",
                    asset=f"{host.ip}:{port.number}",
                    evidence=f"version evidence: {m.group(0)}",
                    description=note,
                    why_it_matters="Outdated builds may carry known, patched vulnerabilities.",
                    severity=sev, confidence=Confidence.LOW,
                    impact="Exposure to known CVEs IF the exact build is affected.",
                    remediation="Confirm the exact version and patch level; update to a supported release.",
                    validation=ValidationState.NEEDS_VALIDATION,
                    source="vuln-heuristic", category="outdated-software",
                ))
    return out


def check_plaintext_protocols(host: Host, port: Port) -> list[Finding]:
    name = port.service.name.lower()
    plaintext = {"telnet": 23, "ftp": 21, "http": 80, "pop3": 110,
                 "imap": 143, "smtp": 25}
    if name in plaintext and name != "http":  # http handled by http-probe (headers)
        return [Finding(
            title=f"Cleartext protocol in use: {name}",
            asset=f"{host.ip}:{port.number}",
            evidence=f"{name} on port {port.number}",
            description=f"{name} transmits data (and often credentials) without encryption.",
            why_it_matters="Traffic can be intercepted or modified by a network attacker.",
            severity=Severity.MEDIUM if name in ("telnet", "ftp") else Severity.LOW,
            confidence=port.service.confidence,
            remediation=f"Replace {name} with an encrypted equivalent (e.g. SSH, FTPS/SFTP, IMAPS).",
            validation=ValidationState.OBSERVED, source="vuln-heuristic", category="crypto",
        )]
    return []


ALL_HOST_PORT_CHECKS = [
    check_sensitive_exposure,
    check_version_hints,
    check_plaintext_protocols,
]

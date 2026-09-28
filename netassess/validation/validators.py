"""Built-in validators.

All checks here are non-destructive:

  * ``ApplicabilityValidator`` — pure logic over evidence already collected. It
    grades a CVE candidate by how trustworthy its version evidence is, keeping
    well-evidenced leads as NEEDS_VALIDATION ("Candidate") and demoting weakly
    evidenced ones to POTENTIAL ("Unconfirmed") so they weigh less.
  * ``NonDestructiveValidator`` — annotates findings that a live prober already
    confirmed via a safe, read-only check (open relay, unauth Redis, anon LDAP,
    directory listing, …) so the report shows *how* they were validated.
  * ``CredentialedValidator`` — OPT-IN. Uses key-based SSH (via the system
    ``ssh`` binary, read-only command) to confirm the exact package/patch level
    of a CVE candidate. Off unless ``--auth-config`` is supplied; never handles
    passwords; never runs a state-changing command.

No exploitation / active-PoC validator ships. The framework supports adding one,
but that stays gated behind explicit authorization by design.
"""
from __future__ import annotations

import json
import os
import re
from typing import Optional

from ..models import Confidence, Finding, Host, Port, ValidationState
from .base import ValidationResult, Validator

# service confidence -> is the product/version from an authoritative signal?
_AUTHORITATIVE = {Confidence.HIGH, Confidence.MEDIUM}
# evidence phrases that indicate the version came from a real, active response
_STRONG_EVIDENCE = ("service detection", "banner:", "server header", "handshake")


class ApplicabilityValidator(Validator):
    """Grade CVE candidates by evidence strength (non-destructive, pure logic)."""
    name = "applicability"

    def applies(self, finding: Finding, host: Host, port: Optional[Port]) -> bool:
        return (finding.category == "known-vulnerability"
                and finding.validation == ValidationState.NEEDS_VALIDATION)

    def validate(self, finding: Finding, host: Host,
                 port: Optional[Port]) -> Optional[ValidationResult]:
        svc_conf = port.service.confidence if port and port.service else Confidence.LOW
        ev = (finding.evidence or "").lower()
        strong_phrase = any(p in ev for p in _STRONG_EVIDENCE)
        has_version = "matched version" in ev or bool(re.search(r"\d+\.\d+", ev))

        strong = has_version and (svc_conf in _AUTHORITATIVE or strong_phrase)
        if strong:
            return ValidationResult(
                state=ValidationState.NEEDS_VALIDATION,     # stays a Candidate
                method="applicability",
                reasoning="Product and affected version confirmed from an active "
                          "service response; the published affected-range applies. "
                          "Exact build/patch level still unverified (back-ported "
                          "fixes can make a matching version non-vulnerable).",
                next_step="Confirm the exact package/patch level with a credentialed "
                          "check, or run an authorized safe proof-of-concept.",
            )
        # weak evidence -> demote to Unconfirmed and lower confidence so it ranks
        # and scores below well-evidenced candidates
        return ValidationResult(
            state=ValidationState.POTENTIAL,
            method="applicability",
            confidence=Confidence.LOW,
            reasoning="Version evidence is low-confidence (inferred rather than "
                      "read from an authoritative banner/handshake); applicability "
                      "to this host is uncertain.",
            next_step="Re-detect the service with deeper probing to obtain an "
                      "authoritative version before prioritising.",
        )


# sources whose findings come from a direct, safe, active check against the
# service (the prober already proved the condition live and marked CONFIRMED)
_ACTIVE_SAFE_SOURCES = {
    "smtp-probe", "database-probe", "redis-probe", "ldap-probe", "snmp-probe",
    "http-probe", "remote-probe", "ftp-probe", "nfs-probe",
}


class NonDestructiveValidator(Validator):
    """Tag already-confirmed live findings with the validation method used."""
    name = "non-destructive"

    def applies(self, finding: Finding, host: Host, port: Optional[Port]) -> bool:
        return (finding.validation == ValidationState.CONFIRMED
                and not finding.validation_method
                and finding.source in _ACTIVE_SAFE_SOURCES)

    def validate(self, finding: Finding, host: Host,
                 port: Optional[Port]) -> Optional[ValidationResult]:
        return ValidationResult(
            state=ValidationState.CONFIRMED,
            method="non-destructive",
            reasoning="Confirmed by a direct, read-only check against the live "
                      "service — the vulnerable condition was observed, without "
                      "exploitation or any state change.",
        )


# read-only commands used to pin down the exact installed version, per family.
_PKG_QUERY = (
    "cat /etc/os-release 2>/dev/null; "
    "command -v dpkg-query >/dev/null 2>&1 && dpkg-query -W 2>/dev/null; "
    "command -v rpm >/dev/null 2>&1 && rpm -qa 2>/dev/null"
)


class CredentialedValidator(Validator):
    """OPT-IN credentialed confirmation over key-based SSH (read-only).

    Enabled only when ``config.validation_credentialed`` is set and an auth-config
    JSON is provided. The auth-config maps a host IP to key-based SSH parameters:

        {"192.0.2.10": {"user": "audit", "key": "~/.ssh/audit_ed25519", "port": 22}}

    Only key authentication is supported (BatchMode=yes); passwords are never
    entered. The command run is strictly read-only. Credentials are never logged
    or written to findings.
    """
    name = "credentialed"

    def __init__(self, auth: Optional[dict] = None, ssh_bin: str = "ssh"):
        self.auth = auth or {}
        self.ssh_bin = ssh_bin

    @classmethod
    def from_config(cls, config) -> Optional["CredentialedValidator"]:
        if not getattr(config, "validation_credentialed", False):
            return None
        path = getattr(config, "auth_config", None)
        if not path or not os.path.isfile(path):
            return None
        try:
            with open(path, "r", encoding="utf-8") as fh:
                auth = json.load(fh)
        except (OSError, ValueError):
            return None
        from ..adapters.process import which
        ssh = which("ssh")
        if not ssh:
            return None
        return cls(auth=auth, ssh_bin=ssh)

    def applies(self, finding: Finding, host: Host, port: Optional[Port]) -> bool:
        if finding.category != "known-vulnerability":
            return False
        if host.ip not in self.auth:
            return False
        # need SSH reachable on the host
        return 22 in host.ports or "port" in self.auth.get(host.ip, {})

    def validate(self, finding: Finding, host: Host,
                 port: Optional[Port]) -> Optional[ValidationResult]:
        creds = self.auth.get(host.ip) or {}
        user = creds.get("user")
        key = creds.get("key")
        if not user or not key:
            return None
        ssh_port = int(creds.get("port", 22))
        installed = self._read_versions(host.ip, user, os.path.expanduser(key), ssh_port)
        if installed is None:
            return None    # unreachable / auth failed -> leave prior state
        # correlate: does any installed package name from the finding appear?
        product = _product_hint(finding)
        matched = ""
        if product:
            for line in installed.splitlines():
                if product.lower() in line.lower():
                    matched = line.strip()
                    break
        if matched:
            return ValidationResult(
                state=ValidationState.CONFIRMED,
                method="credentialed",
                confidence=Confidence.HIGH,
                evidence=f"installed package (credentialed, read-only): {matched}",
                reasoning="Exact installed version confirmed on the host via a "
                          "read-only credentialed check; the affected build is "
                          "present.",
                next_step="Apply the vendor-fixed release / patch level.",
            )
        # we got in but couldn't find the package -> likely not installed as detected
        return ValidationResult(
            state=ValidationState.POTENTIAL,
            method="credentialed",
            reasoning="Credentialed check succeeded but the affected package was "
                      "not found at the detected version — the network banner may "
                      "be a proxy/load-balancer or a back-ported build.",
            next_step="Verify which component actually serves this port.",
        )

    def _read_versions(self, ip: str, user: str, key: str, port: int) -> Optional[str]:
        from ..adapters.process import run
        argv = [
            self.ssh_bin, "-i", key, "-p", str(port),
            "-o", "BatchMode=yes",                 # key only; never prompt for a password
            "-o", "StrictHostKeyChecking=accept-new",
            "-o", "ConnectTimeout=8",
            f"{user}@{ip}", _PKG_QUERY,
        ]
        res = run(argv, timeout=25.0)
        if res.not_found or res.returncode != 0 or not res.stdout:
            return None
        return res.stdout


def _product_hint(finding: Finding) -> str:
    """Best-guess package name from a CVE finding title, e.g. 'CVE-… : OpenSSH'."""
    _, _, tail = finding.title.partition(":")
    name = tail.strip() or finding.title
    name = re.split(r"[ /]", name.strip())[0] if name else ""
    return name.strip()

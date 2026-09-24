"""Core data models for the network assessment platform.

Every module speaks in these structured types instead of raw strings/dicts so the
asset graph stays queryable and serialisable. All models round-trip to plain
dicts via ``to_dict`` / ``from_dict`` for JSON persistence and reporting.
"""
from __future__ import annotations

import time
from dataclasses import dataclass, field, asdict
from enum import Enum
from typing import Any, Optional


def now_ts() -> float:
    return time.time()


def iso(ts: Optional[float] = None) -> str:
    ts = ts if ts is not None else now_ts()
    return time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime(ts))


# --------------------------------------------------------------------------- #
# Enumerations
# --------------------------------------------------------------------------- #
class HostStatus(str, Enum):
    LIVE = "LIVE"
    UNRESPONSIVE = "UNRESPONSIVE"
    FILTERED = "FILTERED"
    UNKNOWN = "UNKNOWN"


class PortState(str, Enum):
    OPEN = "open"
    CLOSED = "closed"
    FILTERED = "filtered"
    OPEN_FILTERED = "open|filtered"


class Confidence(str, Enum):
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"


class Severity(str, Enum):
    INFO = "info"
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"


class ValidationState(str, Enum):
    """Lifecycle of a finding. We never jump straight to CONFIRMED."""
    INFO = "INFO"
    OBSERVED = "OBSERVED"
    POTENTIAL = "POTENTIAL"
    NEEDS_VALIDATION = "NEEDS_VALIDATION"
    CONFIRMED = "CONFIRMED"
    FALSE_POSITIVE = "FALSE_POSITIVE"


# --------------------------------------------------------------------------- #
# Structured records
# --------------------------------------------------------------------------- #
@dataclass
class Service:
    name: str = "unknown"
    product: str = ""
    version: str = ""
    protocol: str = "tcp"
    confidence: Confidence = Confidence.LOW
    banner: str = ""
    evidence: str = ""

    def to_dict(self) -> dict:
        d = asdict(self)
        d["confidence"] = self.confidence.value
        return d


@dataclass
class Port:
    number: int
    protocol: str = "tcp"
    state: PortState = PortState.OPEN
    service: Service = field(default_factory=Service)
    latency_ms: Optional[float] = None
    first_seen: str = field(default_factory=iso)

    def to_dict(self) -> dict:
        return {
            "number": self.number,
            "protocol": self.protocol,
            "state": self.state.value,
            "service": self.service.to_dict(),
            "latency_ms": self.latency_ms,
            "first_seen": self.first_seen,
        }


@dataclass
class Technology:
    name: str
    version: str = ""
    category: str = ""
    evidence: str = ""
    confidence: Confidence = Confidence.LOW

    def to_dict(self) -> dict:
        d = asdict(self)
        d["confidence"] = self.confidence.value
        return d


@dataclass
class TLSInfo:
    subject: str = ""
    issuer: str = ""
    sans: list[str] = field(default_factory=list)
    not_before: str = ""
    not_after: str = ""
    expired: bool = False
    days_to_expiry: Optional[int] = None
    self_signed: bool = False
    hostname_match: Optional[bool] = None
    negotiated_protocol: str = ""
    negotiated_cipher: str = ""
    protocols_offered: list[str] = field(default_factory=list)
    problems: list[str] = field(default_factory=list)

    def to_dict(self) -> dict:
        return asdict(self)


@dataclass
class HTTPService:
    url: str
    ip: str
    port: int
    scheme: str = "http"
    status: Optional[int] = None
    title: str = ""
    server: str = ""
    content_type: str = ""
    content_length: Optional[int] = None
    redirect_chain: list[str] = field(default_factory=list)
    headers: dict[str, str] = field(default_factory=dict)
    security_headers: dict[str, bool] = field(default_factory=dict)
    technologies: list[Technology] = field(default_factory=list)
    tls: Optional[TLSInfo] = None
    response_ms: Optional[float] = None
    favicon_hash: str = ""
    discovered_paths: list[dict] = field(default_factory=list)

    def to_dict(self) -> dict:
        d = asdict(self)
        d["technologies"] = [t.to_dict() for t in self.technologies]
        d["tls"] = self.tls.to_dict() if self.tls else None
        return d


@dataclass
class Finding:
    title: str
    asset: str                      # e.g. "192.0.2.10:443"
    description: str = ""
    evidence: str = ""
    why_it_matters: str = ""
    severity: Severity = Severity.INFO
    confidence: Confidence = Confidence.LOW
    impact: str = ""
    remediation: str = ""
    validation: ValidationState = ValidationState.OBSERVED
    source: str = "netassess"       # detection source / adapter
    category: str = "general"
    ts: str = field(default_factory=iso)

    def to_dict(self) -> dict:
        d = asdict(self)
        d["severity"] = self.severity.value
        d["confidence"] = self.confidence.value
        d["validation"] = self.validation.value
        return d


@dataclass
class Host:
    ip: str
    status: HostStatus = HostStatus.UNKNOWN
    hostnames: list[str] = field(default_factory=list)
    discovery_method: str = ""
    latency_ms: Optional[float] = None
    ports: dict[int, Port] = field(default_factory=dict)
    http_services: list[HTTPService] = field(default_factory=list)
    findings: list[Finding] = field(default_factory=list)
    tls: dict[int, TLSInfo] = field(default_factory=dict)
    notes: list[str] = field(default_factory=list)
    first_seen: str = field(default_factory=iso)
    last_updated: str = field(default_factory=iso)

    # convenience -------------------------------------------------------- #
    def open_ports(self) -> list[Port]:
        return [p for p in self.ports.values() if p.state == PortState.OPEN]

    def add_finding(self, f: Finding) -> None:
        # de-dupe on (title, asset)
        for existing in self.findings:
            if existing.title == f.title and existing.asset == f.asset:
                return
        self.findings.append(f)

    def touch(self) -> None:
        self.last_updated = iso()

    def to_dict(self) -> dict:
        return {
            "ip": self.ip,
            "status": self.status.value,
            "hostnames": self.hostnames,
            "discovery_method": self.discovery_method,
            "latency_ms": self.latency_ms,
            "ports": {str(k): v.to_dict() for k, v in self.ports.items()},
            "http_services": [h.to_dict() for h in self.http_services],
            "findings": [f.to_dict() for f in self.findings],
            "tls": {str(k): v.to_dict() for k, v in self.tls.items()},
            "notes": self.notes,
            "first_seen": self.first_seen,
            "last_updated": self.last_updated,
        }


# Ordering helpers used across the platform ---------------------------------- #
SEVERITY_ORDER = {
    Severity.CRITICAL: 4,
    Severity.HIGH: 3,
    Severity.MEDIUM: 2,
    Severity.LOW: 1,
    Severity.INFO: 0,
}

CONFIDENCE_ORDER = {
    Confidence.HIGH: 2,
    Confidence.MEDIUM: 1,
    Confidence.LOW: 0,
}

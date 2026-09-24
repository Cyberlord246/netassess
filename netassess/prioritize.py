"""Risk / priority engine.

Scores each open service as an attack surface using explainable evidence.
Presence of a service alone never yields a "critical" score — severity is
weighted by confidence and validation state, and every score carries a written
rationale.
"""
from __future__ import annotations

from dataclasses import dataclass, field

from .models import (
    CONFIDENCE_ORDER, Confidence, Host, SEVERITY_ORDER, Severity,
    ValidationState,
)
from .services import is_http, is_tls
from .state import AssetGraph


@dataclass
class PriorityItem:
    asset: str
    score: float
    reasons: list[str] = field(default_factory=list)
    top_severity: str = "info"


_SENSITIVE = {"telnet", "ftp", "rdp", "vnc", "smb", "snmp", "docker",
              "redis", "mongodb", "mysql", "postgresql", "mssql",
              "elasticsearch", "memcached", "microsoft-ds"}


class PriorityEngine:
    def prioritize(self, graph: AssetGraph) -> list[PriorityItem]:
        items: list[PriorityItem] = []
        for host in graph.hosts.values():
            for port in host.open_ports():
                asset = f"{host.ip}:{port.number}"
                score = 0.0
                reasons: list[str] = []
                svc = port.service

                # base: any reachable service is a small surface
                score += 1.0

                if svc.name in _SENSITIVE:
                    score += 3.0
                    reasons.append(f"sensitive service ({svc.name})")

                if is_http(port):
                    score += 1.5
                    reasons.append("web application surface")

                if is_tls(port):
                    score += 0.5
                    reasons.append("TLS endpoint (crypto config matters)")

                # findings on this asset drive most of the weight
                top_sev = Severity.INFO
                for f in host.findings:
                    if f.asset != asset:
                        continue
                    weight = SEVERITY_ORDER[f.severity] * (
                        1.0 + 0.5 * CONFIDENCE_ORDER[f.confidence])
                    # confirmed findings weigh more than unvalidated hints
                    if f.validation == ValidationState.CONFIRMED:
                        weight *= 1.5
                    elif f.validation in (ValidationState.NEEDS_VALIDATION,
                                          ValidationState.POTENTIAL):
                        weight *= 0.7
                    score += weight
                    if SEVERITY_ORDER[f.severity] > SEVERITY_ORDER[top_sev]:
                        top_sev = f.severity
                    if f.severity in (Severity.HIGH, Severity.CRITICAL):
                        reasons.append(f"{f.severity.value} finding: {f.title}")

                # admin/auth surface hint from http titles
                for s in host.http_services:
                    if s.port == port.number and any(
                        w in (s.title or "").lower()
                        for w in ("login", "admin", "console", "dashboard")):
                        score += 1.0
                        reasons.append("authentication/admin interface")
                        break

                if not reasons:
                    reasons.append("reachable service (baseline surface)")

                items.append(PriorityItem(
                    asset=asset, score=round(score, 2), reasons=reasons,
                    top_severity=top_sev.value,
                ))
        items.sort(key=lambda i: i.score, reverse=True)
        return items

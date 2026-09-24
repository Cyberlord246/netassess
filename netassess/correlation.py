"""Correlation engine.

Builds explicit IP -> hostname -> port -> service -> version -> technology ->
finding chains from the asset graph so the report and prioritiser can reason
over connected evidence rather than isolated facts.
"""
from __future__ import annotations

from dataclasses import dataclass, field

from .models import Host
from .state import AssetGraph


@dataclass
class CorrelatedAsset:
    ip: str
    hostnames: list[str]
    port: int
    protocol: str
    service: str
    version: str
    technologies: list[str] = field(default_factory=list)
    findings: list[str] = field(default_factory=list)
    tls_summary: str = ""

    def chain(self) -> str:
        parts = [self.ip]
        if self.hostnames:
            parts.append(self.hostnames[0])
        parts += [f"{self.port}/{self.protocol}", self.service or "unknown"]
        if self.version:
            parts.append(self.version)
        for t in self.technologies:
            parts.append(t)
        return " -> ".join(parts)


class CorrelationEngine:
    def correlate(self, graph: AssetGraph) -> list[CorrelatedAsset]:
        out: list[CorrelatedAsset] = []
        for host in graph.hosts.values():
            http_by_port = {s.port: s for s in host.http_services}
            for port in host.open_ports():
                svc = port.service
                version = " ".join(x for x in (svc.product, svc.version) if x).strip()
                techs = []
                http = http_by_port.get(port.number)
                if http:
                    techs = [f"{t.name}{('/' + t.version) if t.version else ''}"
                             for t in http.technologies]
                tls = host.tls.get(port.number)
                tls_summary = ""
                if tls:
                    tls_summary = f"{tls.negotiated_protocol} {tls.negotiated_cipher}".strip()
                    if tls.problems:
                        tls_summary += f" [{'; '.join(tls.problems)}]"
                related = [f.title for f in host.findings
                           if f.asset == f"{host.ip}:{port.number}"]
                out.append(CorrelatedAsset(
                    ip=host.ip, hostnames=host.hostnames, port=port.number,
                    protocol=port.protocol, service=svc.name, version=version,
                    technologies=techs, findings=related, tls_summary=tls_summary,
                ))
        return out

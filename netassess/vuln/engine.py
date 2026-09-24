"""Vulnerability-assessment engine.

Runs the safe heuristic checks over the asset graph and, when available,
normalises results from an external scanner adapter into the same Finding
schema. All checks are non-destructive and evidence-gated.
"""
from __future__ import annotations

from ..config import Config
from ..models import Host, Port
from ..state import AssetGraph
from .checks import ALL_HOST_PORT_CHECKS


class VulnAssessmentEngine:
    def __init__(self, config: Config, scanner_adapters=None):
        self.config = config
        self.scanner_adapters = scanner_adapters or []

    def assess_host(self, host: Host) -> int:
        added = 0
        for port in host.open_ports():
            for check in ALL_HOST_PORT_CHECKS:
                for finding in check(host, port):
                    before = len(host.findings)
                    host.add_finding(finding)
                    if len(host.findings) > before:
                        added += 1
        return added

    def assess(self, graph: AssetGraph) -> int:
        total = 0
        for host in graph.hosts.values():
            total += self.assess_host(host)
        # external scanners (normalised) — optional, only if configured/available
        for adapter in self.scanner_adapters:
            if getattr(adapter, "available", lambda: False)():
                total += self._run_external(adapter, graph)
        return total

    def _run_external(self, adapter, graph: AssetGraph) -> int:
        """Hook for VulnerabilityScannerAdapter integrations.

        Each adapter is expected to return a list of Finding objects already
        mapped into our schema. Kept as a no-op-safe hook so the platform runs
        fully without any external scanner installed.
        """
        added = 0
        try:
            findings = adapter.scan(graph)  # returns list[Finding]
        except Exception:
            return 0
        for f in findings or []:
            ip = f.asset.split(":", 1)[0]
            host = graph.get(ip)
            if host is not None:
                before = len(host.findings)
                host.add_finding(f)
                if len(host.findings) > before:
                    added += 1
        return added

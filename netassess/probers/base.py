"""Service-prober interface + registry.

A ServiceProbe performs *safe, non-destructive* enumeration of one service.
Probes never attempt authentication attacks, never write/modify remote state,
and always go through the Scope Engine (via the slot the caller already holds,
or by re-authorizing before any new connection).

Each probe returns a ProbeResult carrying structured data + findings, which the
engine merges into the asset graph.
"""
from __future__ import annotations

from abc import ABC, abstractmethod
from dataclasses import dataclass, field

from ..config import Config
from ..models import Finding, Host, Port
from ..scope import ScopeEngine


@dataclass
class ProbeResult:
    data: dict = field(default_factory=dict)
    findings: list[Finding] = field(default_factory=list)
    error: str = ""


class ServiceProbe(ABC):
    name: str = "generic"

    def __init__(self, config: Config, scope: ScopeEngine):
        self.config = config
        self.scope = scope

    @abstractmethod
    def matches(self, port: Port) -> bool:
        """True if this probe applies to the given open port."""

    @abstractmethod
    def probe(self, host: Host, port: Port) -> ProbeResult:
        """Run the safe enumeration. Must self-check scope before connecting."""

    # helper for subclasses
    def in_scope(self, ip: str, port: int) -> bool:
        return self.scope.authorize(ip, port).allowed

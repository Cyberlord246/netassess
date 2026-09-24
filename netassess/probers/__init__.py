"""Prober registry.

``build_probes(config, scope)`` returns an ordered list of instantiated probes.
The engine asks each probe ``matches(port)`` and runs the specific ones; the
GenericProbe is the catch-all fallback and is tried last.
"""
from __future__ import annotations

from ..config import Config
from ..scope import ScopeEngine
from .base import ProbeResult, ServiceProbe
from .http_probe import HTTPProbe
from .tls_probe import TLSProbe
from .service_probes import (
    DNSProbe, DatabaseProbe, GenericProbe, SMBProbe, SMTPProbe, SSHProbe,
)

# Order matters: specific probes first, generic last.
SPECIFIC_PROBE_CLASSES = [
    HTTPProbe, TLSProbe, SSHProbe, SMTPProbe, DNSProbe, SMBProbe, DatabaseProbe,
]


def build_probes(config: Config, scope: ScopeEngine) -> list[ServiceProbe]:
    return [cls(config, scope) for cls in SPECIFIC_PROBE_CLASSES]


def build_generic(config: Config, scope: ScopeEngine) -> ServiceProbe:
    return GenericProbe(config, scope)


__all__ = [
    "ProbeResult", "ServiceProbe", "build_probes", "build_generic",
    "HTTPProbe", "TLSProbe", "SSHProbe", "SMTPProbe", "DNSProbe", "SMBProbe",
    "DatabaseProbe", "GenericProbe",
]

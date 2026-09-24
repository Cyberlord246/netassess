"""Scope Engine + Policy Engine.

This is the single mandatory gate that guards every network-active operation.
No adapter, prober, discovery task, or AI decision may touch the network without
first passing ``ScopeEngine.authorize(...)`` and receiving an ``ALLOW`` verdict.

Design rules enforced here:
  * Only the *originally configured* IPs/CIDRs are in scope.
  * Hosts discovered during assessment are NEVER auto-added to scope.
  * Excluded IPs/CIDRs always win over included ones.
  * Forbidden ports are rejected regardless of caller intent.
  * Every decision is logged with a reason.
"""
from __future__ import annotations

import ipaddress
import threading
import time
from dataclasses import dataclass, field
from enum import Enum
from typing import Optional

from .config import Config


class Verdict(str, Enum):
    ALLOW = "ALLOW"
    DENY = "DENY"


@dataclass
class ScopeDecision:
    verdict: Verdict
    target: str
    port: Optional[int]
    reason: str
    ts: float = field(default_factory=time.time)

    @property
    def allowed(self) -> bool:
        return self.verdict is Verdict.ALLOW


Network = ipaddress._BaseNetwork  # type: ignore[attr-defined]


def parse_targets(raw: list[str]) -> tuple[list[Network], list[str]]:
    """Parse a mixed list of IPs/CIDRs/hostfile-lines into networks.

    Returns (networks, errors). Bare IPs become /32 (or /128) networks.
    """
    nets: list[Network] = []
    errors: list[str] = []
    seen: set[str] = set()
    for item in raw:
        item = item.strip()
        if not item or item.startswith("#"):
            continue
        try:
            if "/" in item:
                net = ipaddress.ip_network(item, strict=False)
            else:
                ip = ipaddress.ip_address(item)
                net = ipaddress.ip_network(f"{ip}/{ip.max_prefixlen}", strict=False)
        except ValueError as exc:
            errors.append(f"{item}: {exc}")
            continue
        key = str(net)
        if key not in seen:
            seen.add(key)
            nets.append(net)
    return nets, errors


class TokenBucket:
    """Thread-safe rate limiter (connections per second)."""

    def __init__(self, rate: float, capacity: Optional[float] = None):
        self.rate = max(rate, 0.1)
        self.capacity = capacity if capacity is not None else max(rate, 1.0)
        self._tokens = self.capacity
        self._last = time.monotonic()
        self._lock = threading.Lock()

    def acquire(self, tokens: float = 1.0) -> None:
        while True:
            with self._lock:
                now = time.monotonic()
                self._tokens = min(
                    self.capacity, self._tokens + (now - self._last) * self.rate
                )
                self._last = now
                if self._tokens >= tokens:
                    self._tokens -= tokens
                    return
                needed = (tokens - self._tokens) / self.rate
            time.sleep(min(needed, 0.25))


class ScopeEngine:
    """Mandatory authorization gate. Instantiate once, share everywhere."""

    def __init__(self, config: Config):
        self.config = config
        self.include, inc_err = parse_targets(config.targets)
        self.exclude, exc_err = parse_targets(config.exclude)
        self.parse_errors = inc_err + exc_err
        self.forbidden_ports = set(config.forbidden_ports)
        self._bucket = TokenBucket(config.rate)
        self._sem = threading.BoundedSemaphore(max(1, config.concurrency))
        self.decisions: list[ScopeDecision] = []
        self._log_lock = threading.Lock()

    # -- introspection ---------------------------------------------------- #
    def expand_hosts(self, max_hosts: int = 65536) -> list[str]:
        """Enumerate individual in-scope host IPs (minus exclusions)."""
        out: list[str] = []
        for net in self.include:
            hosts = net.hosts() if net.num_addresses > 2 else net
            for ip in hosts:
                if len(out) >= max_hosts:
                    return out
                if not self._is_excluded(ip):
                    out.append(str(ip))
        return out

    def _in_networks(self, ip: ipaddress._BaseAddress, nets: list[Network]) -> bool:
        return any(ip in net for net in nets)

    def _is_excluded(self, ip: ipaddress._BaseAddress) -> bool:
        return self._in_networks(ip, self.exclude)

    def _is_included(self, ip: ipaddress._BaseAddress) -> bool:
        return self._in_networks(ip, self.include)

    # -- the gate --------------------------------------------------------- #
    def authorize(self, target: str, port: Optional[int] = None) -> ScopeDecision:
        """Return an ALLOW/DENY decision. ALWAYS call before a network op."""
        try:
            ip = ipaddress.ip_address(target)
        except ValueError:
            return self._log(Verdict.DENY, target, port,
                             "target is not a valid IP address")

        if not self._is_included(ip):
            return self._log(Verdict.DENY, target, port,
                             "target is outside the authorized scope")
        if self._is_excluded(ip):
            return self._log(Verdict.DENY, target, port,
                             "target is in the exclusion list")
        if port is not None and port in self.forbidden_ports:
            return self._log(Verdict.DENY, target, port,
                             f"port {port} is policy-forbidden")
        if port is not None and not (0 < port <= 65535):
            return self._log(Verdict.DENY, target, port, "port out of range")

        return self._log(Verdict.ALLOW, target, port, "in scope")

    def guard(self, target: str, port: Optional[int] = None) -> bool:
        """Convenience: authorize + apply rate/concurrency policy.

        Returns True and consumes a rate token / must be paired with
        ``release()`` when True. Use the ``slot`` context manager instead where
        possible.
        """
        decision = self.authorize(target, port)
        if not decision.allowed:
            return False
        self._sem.acquire()
        self._bucket.acquire()
        return True

    def release(self) -> None:
        try:
            self._sem.release()
        except ValueError:
            pass

    def slot(self, target: str, port: Optional[int] = None) -> "_Slot":
        return _Slot(self, target, port)

    # -- logging ---------------------------------------------------------- #
    def _log(self, verdict: Verdict, target: str, port: Optional[int],
             reason: str) -> ScopeDecision:
        d = ScopeDecision(verdict, target, port, reason)
        with self._log_lock:
            self.decisions.append(d)
        return d

    def denied_decisions(self) -> list[ScopeDecision]:
        return [d for d in self.decisions if not d.allowed]

    def summary(self) -> dict:
        allow = sum(1 for d in self.decisions if d.allowed)
        deny = len(self.decisions) - allow
        return {
            "included_networks": [str(n) for n in self.include],
            "excluded_networks": [str(n) for n in self.exclude],
            "forbidden_ports": sorted(self.forbidden_ports),
            "authorized_ops": allow,
            "denied_ops": deny,
            "parse_errors": self.parse_errors,
        }


class _Slot:
    """Context manager: authorize once, hold a concurrency+rate slot."""

    def __init__(self, engine: ScopeEngine, target: str, port: Optional[int]):
        self.engine = engine
        self.target = target
        self.port = port
        self.decision: Optional[ScopeDecision] = None
        self.granted = False

    def __enter__(self) -> "_Slot":
        self.decision = self.engine.authorize(self.target, self.port)
        if self.decision.allowed:
            self.engine._sem.acquire()
            self.engine._bucket.acquire()
            self.granted = True
        return self

    def __exit__(self, *exc) -> None:
        if self.granted:
            self.engine.release()

    @property
    def allowed(self) -> bool:
        return bool(self.decision and self.decision.allowed)

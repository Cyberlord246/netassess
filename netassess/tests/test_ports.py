"""Tests for concurrent multi-host scanning (network mocked).

Run: python -m netassess.tests.test_ports
"""
from __future__ import annotations

from ..config import Config
from ..models import Port, PortState, Service
from ..ports import PortScanner, effective_timeout
from ..scope import ScopeEngine


def _scanner(targets):
    cfg = Config(targets=list(targets), concurrency=20)
    return PortScanner(cfg, ScopeEngine(cfg), nmap_adapter=None)


def test_scan_hosts_groups_results_per_host():
    s = _scanner(["192.0.2.10/32", "192.0.2.11/32"])
    assert s.backend == "python"
    # fake: port "open" only when port==80, for any host
    def fake(ip, p, timeout=None):
        if p == 80:
            return Port(80, state=PortState.OPEN, service=Service(name="http"))
        return None
    s.pure.scan_port = fake
    out = s.scan_hosts(["192.0.2.10", "192.0.2.11"], ports=[22, 80, 443])
    assert set(out) == {"192.0.2.10", "192.0.2.11"}
    assert [p.number for p in out["192.0.2.10"]] == [80]
    assert [p.number for p in out["192.0.2.11"]] == [80]


def test_scan_hosts_covers_all_host_port_pairs():
    s = _scanner(["192.0.2.0/29"])
    seen = []
    def fake(ip, p, timeout=None):
        seen.append((ip, p))
        return None
    s.pure.scan_port = fake
    hosts = ["192.0.2.1", "192.0.2.2", "192.0.2.3"]
    s.scan_hosts(hosts, ports=[80, 443])
    # every (host, port) pair was attempted exactly once
    assert sorted(seen) == sorted((h, p) for h in hosts for p in (80, 443))


def test_scan_hosts_results_sorted():
    s = _scanner(["192.0.2.10/32"])
    def fake(ip, p, timeout=None):
        return Port(p, state=PortState.OPEN, service=Service(name="x"))
    s.pure.scan_port = fake
    out = s.scan_hosts(["192.0.2.10"], ports=[443, 22, 80])
    assert [p.number for p in out["192.0.2.10"]] == [22, 80, 443]  # sorted


def test_scan_hosts_empty_when_no_ports():
    s = _scanner(["192.0.2.10/32"])
    assert s.scan_hosts(["192.0.2.10"], ports=[]) == {"192.0.2.10": []}


# --- adaptive timeout ------------------------------------------------------ #
def test_effective_timeout_fast_host_tightens():
    cfg = Config(timeout=3.0, adaptive_timeout=True, adaptive_factor=10, adaptive_floor=0.3)
    # 20ms RTT -> 0.02*10 = 0.2 -> floored to 0.3 (well below the 3s ceiling)
    assert effective_timeout(20.0, cfg) == 0.3
    # 120ms RTT -> 1.2s (between floor and ceiling)
    assert abs(effective_timeout(120.0, cfg) - 1.2) < 1e-9


def test_effective_timeout_capped_at_ceiling():
    cfg = Config(timeout=3.0, adaptive_timeout=True, adaptive_factor=10)
    assert effective_timeout(5000.0, cfg) == 3.0     # never exceeds --timeout


def test_effective_timeout_disabled_or_unknown_uses_ceiling():
    cfg = Config(timeout=3.0, adaptive_timeout=True)
    assert effective_timeout(None, cfg) == 3.0        # unknown RTT -> ceiling
    off = Config(timeout=3.0, adaptive_timeout=False)
    assert effective_timeout(10.0, off) == 3.0        # disabled -> ceiling


def test_scan_hosts_passes_per_host_timeout():
    s = _scanner(["192.0.2.10/32", "192.0.2.11/32"])
    got = {}
    def fake(ip, p, timeout=None):
        got[ip] = timeout
        return None
    s.pure.scan_port = fake
    s.scan_hosts(["192.0.2.10", "192.0.2.11"], ports=[80],
                 host_timeouts={"192.0.2.10": 0.3, "192.0.2.11": 1.5})
    assert got == {"192.0.2.10": 0.3, "192.0.2.11": 1.5}


def _run_all():
    fns = [v for k, v in globals().items() if k.startswith("test_")]
    for fn in fns:
        fn()
        print(f"  ok  {fn.__name__}")
    print(f"\n{len(fns)}/{len(fns)} tests passed")


if __name__ == "__main__":
    _run_all()

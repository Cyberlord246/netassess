"""Tests for concurrent multi-host scanning (network mocked).

Run: python -m netassess.tests.test_ports
"""
from __future__ import annotations

from ..config import Config
from ..models import Port, PortState, Service
from ..ports import PortScanner
from ..scope import ScopeEngine


def _scanner(targets):
    cfg = Config(targets=list(targets), concurrency=20)
    return PortScanner(cfg, ScopeEngine(cfg), nmap_adapter=None)


def test_scan_hosts_groups_results_per_host():
    s = _scanner(["192.0.2.10/32", "192.0.2.11/32"])
    assert s.backend == "python"
    # fake: port "open" only when port==80, for any host
    def fake(ip, p):
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
    def fake(ip, p):
        seen.append((ip, p))
        return None
    s.pure.scan_port = fake
    hosts = ["192.0.2.1", "192.0.2.2", "192.0.2.3"]
    s.scan_hosts(hosts, ports=[80, 443])
    # every (host, port) pair was attempted exactly once
    assert sorted(seen) == sorted((h, p) for h in hosts for p in (80, 443))


def test_scan_hosts_results_sorted():
    s = _scanner(["192.0.2.10/32"])
    def fake(ip, p):
        return Port(p, state=PortState.OPEN, service=Service(name="x"))
    s.pure.scan_port = fake
    out = s.scan_hosts(["192.0.2.10"], ports=[443, 22, 80])
    assert [p.number for p in out["192.0.2.10"]] == [22, 80, 443]  # sorted


def test_scan_hosts_empty_when_no_ports():
    s = _scanner(["192.0.2.10/32"])
    assert s.scan_hosts(["192.0.2.10"], ports=[]) == {"192.0.2.10": []}


def _run_all():
    fns = [v for k, v in globals().items() if k.startswith("test_")]
    for fn in fns:
        fn()
        print(f"  ok  {fn.__name__}")
    print(f"\n{len(fns)}/{len(fns)} tests passed")


if __name__ == "__main__":
    _run_all()

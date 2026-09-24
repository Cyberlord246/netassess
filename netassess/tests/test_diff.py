"""Tests for the diff engine.

Run: python -m netassess.tests.test_diff
"""
from __future__ import annotations

from ..diff import diff_graphs
from ..models import (
    Finding, Host, HostStatus, Port, PortState, Service, Severity,
    ValidationState,
)
from ..state import AssetGraph


def _graph(spec):
    """spec: {ip: {"status":..., "ports":{num:(name,ver)}, "findings":[(asset,title,sev)]}}"""
    g = AssetGraph()
    for ip, hd in spec.items():
        h = g.get_or_create(ip)
        h.status = hd.get("status", HostStatus.LIVE)
        for num, (name, ver) in hd.get("ports", {}).items():
            h.ports[num] = Port(number=num, state=PortState.OPEN,
                                service=Service(name=name, version=ver))
        for asset, title, sev in hd.get("findings", []):
            h.add_finding(Finding(title=title, asset=asset, severity=sev,
                                  validation=ValidationState.OBSERVED))
    return g


def test_port_opened_and_closed():
    old = _graph({"192.0.2.10": {"ports": {22: ("ssh", "")}}})
    new = _graph({"192.0.2.10": {"ports": {22: ("ssh", ""), 443: ("https", "")}}})
    d = diff_graphs(old, new)
    assert ("192.0.2.10", 443, "https") in d.ports_opened
    assert not d.ports_closed

    d2 = diff_graphs(new, old)
    assert ("192.0.2.10", 443, "https") in d2.ports_closed
    assert not d2.ports_opened


def test_host_added_removed():
    old = _graph({"192.0.2.10": {}})
    new = _graph({"192.0.2.10": {}, "192.0.2.11": {}})
    d = diff_graphs(old, new)
    assert d.hosts_added == ["192.0.2.11"]
    assert not d.hosts_removed


def test_status_change():
    old = _graph({"192.0.2.10": {"status": HostStatus.FILTERED}})
    new = _graph({"192.0.2.10": {"status": HostStatus.LIVE}})
    d = diff_graphs(old, new)
    assert d.host_status_changed == [("192.0.2.10", "FILTERED", "LIVE")]


def test_service_version_change():
    old = _graph({"192.0.2.10": {"ports": {80: ("http", "1.0")}}})
    new = _graph({"192.0.2.10": {"ports": {80: ("http", "2.0")}}})
    d = diff_graphs(old, new)
    assert d.service_changed and d.service_changed[0][1] == 80
    assert "1.0" in d.service_changed[0][2] and "2.0" in d.service_changed[0][3]


def test_findings_new_and_resolved():
    old = _graph({"192.0.2.10": {
        "findings": [("192.0.2.10:22", "Old issue", Severity.LOW)]}})
    new = _graph({"192.0.2.10": {
        "findings": [("192.0.2.10:443", "New critical", Severity.CRITICAL)]}})
    d = diff_graphs(old, new)
    assert any(f["title"] == "New critical" for f in d.findings_new)
    assert any(f["title"] == "Old issue" for f in d.findings_resolved)
    # sorted most-severe first
    assert d.findings_new[0]["severity"] == "critical"


def test_empty_when_identical():
    g1 = _graph({"192.0.2.10": {"ports": {22: ("ssh", "8.0")}}})
    g2 = _graph({"192.0.2.10": {"ports": {22: ("ssh", "8.0")}}})
    assert diff_graphs(g1, g2).is_empty()


def _run_all():
    fns = [v for k, v in globals().items() if k.startswith("test_")]
    for fn in fns:
        fn()
        print(f"  ok  {fn.__name__}")
    print(f"\n{len(fns)}/{len(fns)} tests passed")


if __name__ == "__main__":
    _run_all()

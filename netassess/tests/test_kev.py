"""Tests for CISA KEV + EPSS enrichment (no network).

Run: python -m netassess.tests.test_kev
"""
from __future__ import annotations

from ..cve.kev import KEVData, cve_in, enrich_graph
from ..models import (
    Finding, Host, Severity, ValidationState,
)
from ..state import AssetGraph


def _data():
    return KEVData(
        kev={"CVE-2021-41773": {"dateAdded": "2021-11-03", "ransomware": False},
             "CVE-2017-0144": {"dateAdded": "2022-01-01", "ransomware": True}},
        epss={"CVE-2021-41773": 0.94, "CVE-2019-20372": 0.12},
    )


def test_cve_extraction():
    assert cve_in("CVE-2021-41773: apache httpd") == "CVE-2021-41773"
    assert cve_in("no cve here") is None


def test_kev_flag_and_severity_floor():
    d = _data()
    f = Finding(title="CVE-2021-41773: apache httpd", asset="192.0.2.10:80",
                severity=Severity.MEDIUM, validation=ValidationState.NEEDS_VALIDATION)
    d.enrich_finding(f)
    assert f.kev is True
    assert f.severity == Severity.HIGH          # floored up from medium
    assert f.epss == 0.94
    assert "actively exploited" in f.evidence.lower()


def test_ransomware_floors_to_critical():
    d = _data()
    f = Finding(title="CVE-2017-0144 (EternalBlue)", asset="192.0.2.10:445",
                severity=Severity.LOW)
    d.enrich_finding(f)
    assert f.kev is True and f.severity == Severity.CRITICAL


def test_epss_only_no_kev():
    d = _data()
    f = Finding(title="CVE-2019-20372: nginx", asset="192.0.2.10:443",
                severity=Severity.MEDIUM)
    d.enrich_finding(f)
    assert f.kev is False and f.epss == 0.12
    assert f.severity == Severity.MEDIUM        # unchanged


def test_non_cve_finding_untouched():
    d = _data()
    f = Finding(title="SMB service reachable", asset="192.0.2.10:445",
                severity=Severity.MEDIUM)
    assert d.enrich_finding(f) is False
    assert f.kev is False and f.epss is None


def test_enrich_graph_counts_and_priority():
    d = _data()
    g = AssetGraph()
    h = g.get_or_create("192.0.2.10")
    h.add_finding(Finding(title="CVE-2021-41773: apache httpd",
                          asset="192.0.2.10:80", severity=Severity.MEDIUM))
    h.add_finding(Finding(title="CVE-2019-20372: nginx",
                          asset="192.0.2.10:443", severity=Severity.MEDIUM))
    counts = enrich_graph(g, d)
    assert counts["kev"] == 1 and counts["epss"] == 2

    # KEV finding should dominate prioritization
    from ..prioritize import PriorityEngine
    # give the host an open port so it's scored
    from ..models import Port, PortState, Service
    h.ports[80] = Port(80, state=PortState.OPEN, service=Service(name="http"))
    items = PriorityEngine().prioritize(g)
    top = items[0]
    assert any("ACTIVELY EXPLOITED" in r for r in top.reasons)


def _run_all():
    fns = [v for k, v in globals().items() if k.startswith("test_")]
    for fn in fns:
        fn()
        print(f"  ok  {fn.__name__}")
    print(f"\n{len(fns)}/{len(fns)} tests passed")


if __name__ == "__main__":
    _run_all()

"""Tests for the findings view: severity floor + cross-host aggregation.

Run: python -m netassess.tests.test_findings_view
"""
from __future__ import annotations

from ..findings_view import build_view
from ..models import Finding, Host, Severity, ValidationState
from ..state import AssetGraph


def _graph_with(findings):
    g = AssetGraph()
    for asset, title, sev in findings:
        ip = asset.split(":", 1)[0]
        g.get_or_create(ip).add_finding(
            Finding(title=title, asset=asset, severity=sev,
                    validation=ValidationState.OBSERVED))
    return g


def test_info_and_low_included_by_default_floor():
    g = _graph_with([
        ("192.0.2.10:80", "Missing HTTP security headers", Severity.LOW),
        ("192.0.2.10:80", "Software version disclosure", Severity.INFO),
        ("192.0.2.10:445", "SMB service reachable", Severity.MEDIUM),
    ])
    view = build_view(g, min_severity="info", aggregate=True)
    titles = {a.title for aggs in view.by_validation.values() for a in aggs}
    assert "Missing HTTP security headers" in titles      # low shown
    assert "Software version disclosure" in titles        # info shown
    assert view.suppressed == 0


def test_same_title_across_hosts_collapses_to_one():
    g = _graph_with([
        ("192.0.2.10:80", "Missing HTTP security headers", Severity.LOW),
        ("192.0.2.11:80", "Missing HTTP security headers", Severity.LOW),
        ("192.0.2.12:80", "Missing HTTP security headers", Severity.LOW),
    ])
    view = build_view(g, min_severity="info", aggregate=True)
    aggs = [a for bucket in view.by_validation.values() for a in bucket]
    hdr = [a for a in aggs if a.title == "Missing HTTP security headers"]
    assert len(hdr) == 1                    # single entry
    assert hdr[0].count == 3                # covering all three hosts
    assert set(hdr[0].assets) == {"192.0.2.10:80", "192.0.2.11:80", "192.0.2.12:80"}


def test_info_across_hosts_single_title():
    g = _graph_with([
        ("192.0.2.10:80", "Software version disclosure", Severity.INFO),
        ("192.0.2.20:80", "Software version disclosure", Severity.INFO),
    ])
    view = build_view(g, min_severity="info", aggregate=True)
    aggs = [a for bucket in view.by_validation.values() for a in bucket]
    disc = [a for a in aggs if a.title == "Software version disclosure"]
    assert len(disc) == 1 and disc[0].count == 2


def test_raising_floor_still_suppresses():
    g = _graph_with([
        ("192.0.2.10:80", "Missing HTTP security headers", Severity.LOW),
        ("192.0.2.10:445", "SMB service reachable", Severity.MEDIUM),
    ])
    view = build_view(g, min_severity="medium", aggregate=True)
    titles = {a.title for aggs in view.by_validation.values() for a in aggs}
    assert "Missing HTTP security headers" not in titles
    assert view.suppressed == 1


def _run_all():
    fns = [v for k, v in globals().items() if k.startswith("test_")]
    for fn in fns:
        fn()
        print(f"  ok  {fn.__name__}")
    print(f"\n{len(fns)}/{len(fns)} tests passed")


if __name__ == "__main__":
    _run_all()

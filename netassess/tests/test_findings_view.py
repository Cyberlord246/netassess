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


def test_suppress_titles_hidden_regardless_of_severity():
    g = _graph_with([
        ("192.0.2.10:80", "Missing HTTP security headers", Severity.LOW),
        ("192.0.2.11:80", "Missing HTTP security headers", Severity.LOW),
        ("192.0.2.10:443", "Deprecated TLS protocol versions enabled", Severity.MEDIUM),
    ])
    view = build_view(g, min_severity="info", aggregate=True,
                      suppress_titles=["Missing HTTP security headers"])
    titles = {a.title for aggs in view.by_validation.values() for a in aggs}
    assert "Missing HTTP security headers" not in titles   # hidden
    assert "Deprecated TLS protocol versions enabled" in titles
    assert view.suppressed == 2                            # both instances counted


def test_no_suppression_when_list_empty():
    g = _graph_with([("192.0.2.10:80", "Missing HTTP security headers", Severity.LOW)])
    view = build_view(g, min_severity="info", aggregate=True, suppress_titles=[])
    titles = {a.title for aggs in view.by_validation.values() for a in aggs}
    assert "Missing HTTP security headers" in titles


def test_same_title_merges_across_differing_severity_and_validation():
    # same title, but different severity + validation per host -> still ONE entry
    g = AssetGraph()
    g.get_or_create("192.0.2.10").add_finding(Finding(
        title="Administrative interface reachable: /admin", asset="192.0.2.10:80",
        severity=Severity.LOW, validation=ValidationState.OBSERVED))
    g.get_or_create("192.0.2.11").add_finding(Finding(
        title="Administrative interface reachable: /admin", asset="192.0.2.11:80",
        severity=Severity.MEDIUM, validation=ValidationState.CONFIRMED))
    view = build_view(g, min_severity="info", aggregate=True)
    aggs = [a for bucket in view.by_validation.values() for a in bucket]
    match = [a for a in aggs if a.title.endswith("/admin")]
    assert len(match) == 1                       # single title entry
    assert match[0].count == 2                   # both hosts
    assert match[0].severity == Severity.MEDIUM  # worst-case severity
    assert match[0].validation == ValidationState.CONFIRMED  # most-confirmed


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

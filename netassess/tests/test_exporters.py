"""Tests for CSV + SARIF export.

Run: python -m netassess.tests.test_exporters
"""
from __future__ import annotations

import json

from ..exporters import to_csv, to_sarif
from ..models import Finding, Severity, ValidationState
from ..state import AssetGraph


def _graph():
    g = AssetGraph()
    h = g.get_or_create("10.0.0.5")
    h.add_finding(Finding(title="SMTP open relay", asset="10.0.0.5:25",
                          severity=Severity.HIGH, category="mail-relay",
                          source="smtp", validation=ValidationState.OBSERVED,
                          evidence="RCPT accepted"))
    f = Finding(title="CVE-2021-1234: nginx RCE", asset="10.0.0.5:443",
                severity=Severity.CRITICAL, category="known-vulnerability",
                source="cve", validation=ValidationState.NEEDS_VALIDATION)
    f.kev = True
    f.epss = 0.9421
    h.add_finding(f)
    return g


def test_csv_has_header_and_rows():
    rows = to_csv(_graph()).strip().splitlines()
    assert rows[0].startswith("host,asset,title,severity")
    assert len(rows) == 3                       # header + 2 findings
    assert any("mail-relay" in r for r in rows)
    assert any("yes" in r and "0.9421" in r for r in rows)   # kev + epss


def test_sarif_is_valid_structure():
    doc = json.loads(to_sarif(_graph()))
    assert doc["version"] == "2.1.0"
    run = doc["runs"][0]
    assert run["tool"]["driver"]["name"] == "netassess"
    assert len(run["results"]) == 2
    levels = {r["level"] for r in run["results"]}
    assert levels == {"error"}                  # high + critical -> error
    # rules are deduped by category; both findings have distinct categories
    rule_ids = {r["id"] for r in run["tool"]["driver"]["rules"]}
    assert "mail-relay" in rule_ids and "known-vulnerability" in rule_ids
    # a result carries the asset + kev property
    props = run["results"][1]["properties"]
    assert props["kev"] is True and abs(props["epss"] - 0.9421) < 1e-6


def _run_all():
    fns = [v for k, v in globals().items() if k.startswith("test_")]
    for fn in fns:
        fn()
        print(f"  ok  {fn.__name__}")
    print(f"\n{len(fns)}/{len(fns)} tests passed")


if __name__ == "__main__":
    _run_all()

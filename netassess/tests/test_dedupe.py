"""Cross-source CVE finding de-dup.

Run: python -m netassess.tests.test_dedupe
"""
from __future__ import annotations

import tempfile

from ..config import Config
from ..engine import AssessmentEngine
from ..models import Confidence, Finding, Severity, ValidationState


def _engine():
    return AssessmentEngine(Config(targets=["192.0.2.10"], show_progress=False,
                                   output_dir=tempfile.mkdtemp(prefix="na-dd-")))


def test_same_cve_same_asset_collapsed_keeping_strongest():
    eng = _engine()
    h = eng.graph.get_or_create("192.0.2.10")
    # offline-KB lead
    h.add_finding(Finding(title="CVE-2021-1234: nginx issue", asset="192.0.2.10:443",
                          severity=Severity.MEDIUM, confidence=Confidence.LOW,
                          validation=ValidationState.NEEDS_VALIDATION, source="cve"))
    # nuclei confirmation of the SAME cve (different title/source)
    h.add_finding(Finding(title="CVE-2021-1234: nginx RCE template match",
                          asset="192.0.2.10:443", severity=Severity.HIGH,
                          confidence=Confidence.HIGH,
                          validation=ValidationState.CONFIRMED, source="nuclei"))
    eng._dedupe_cve_findings()
    cve = [f for f in h.findings if "CVE-2021-1234" in f.title]
    assert len(cve) == 1
    assert cve[0].validation == ValidationState.CONFIRMED   # kept the stronger


def test_different_cves_kept_separate():
    eng = _engine()
    h = eng.graph.get_or_create("192.0.2.10")
    h.add_finding(Finding(title="CVE-2021-1111: a", asset="192.0.2.10:443",
                          severity=Severity.HIGH))
    h.add_finding(Finding(title="CVE-2022-2222: b", asset="192.0.2.10:443",
                          severity=Severity.HIGH))
    eng._dedupe_cve_findings()
    assert len([f for f in h.findings if "CVE-" in f.title]) == 2


def test_same_cve_different_asset_kept():
    eng = _engine()
    h = eng.graph.get_or_create("192.0.2.10")
    h.add_finding(Finding(title="CVE-2021-1234: x", asset="192.0.2.10:443",
                          severity=Severity.HIGH))
    h.add_finding(Finding(title="CVE-2021-1234: x", asset="192.0.2.10:8443",
                          severity=Severity.HIGH))
    eng._dedupe_cve_findings()
    assert len([f for f in h.findings if "CVE-2021-1234" in f.title]) == 2


def test_non_cve_findings_untouched():
    eng = _engine()
    h = eng.graph.get_or_create("192.0.2.10")
    h.add_finding(Finding(title="SMB reachable", asset="192.0.2.10:445",
                          severity=Severity.MEDIUM))
    eng._dedupe_cve_findings()
    assert len(h.findings) == 1


def _run_all():
    fns = [v for k, v in globals().items() if k.startswith("test_")]
    for fn in fns:
        fn()
        print(f"  ok  {fn.__name__}")
    print(f"\n{len(fns)}/{len(fns)} tests passed")


if __name__ == "__main__":
    _run_all()

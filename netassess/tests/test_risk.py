"""Tests for environmental risk scoring.

Run: python -m netassess.tests.test_risk
"""
from __future__ import annotations

from ..models import Confidence, Severity, ValidationState
from ..risk import band, host_risk, score_finding


def test_band_thresholds():
    assert band(95) == "critical"
    assert band(75) == "high"
    assert band(45) == "medium"
    assert band(15) == "low"
    assert band(3) == "info"


def test_false_positive_is_zero():
    s, _ = score_finding(Severity.HIGH, Confidence.HIGH,
                         ValidationState.FALSE_POSITIVE)
    assert s == 0


def test_severity_base_ordering():
    hi, _ = score_finding(Severity.HIGH, Confidence.HIGH, ValidationState.CONFIRMED)
    med, _ = score_finding(Severity.MEDIUM, Confidence.HIGH, ValidationState.CONFIRMED)
    lo, _ = score_finding(Severity.LOW, Confidence.HIGH, ValidationState.CONFIRMED)
    assert hi > med > lo


def test_unconfirmed_dampens():
    conf, _ = score_finding(Severity.HIGH, Confidence.HIGH, ValidationState.CONFIRMED)
    obs, _ = score_finding(Severity.HIGH, Confidence.HIGH, ValidationState.OBSERVED)
    assert obs < conf


def test_kev_floors_high():
    # even a medium, unconfirmed finding jumps to near-max when KEV
    s, reasons = score_finding(Severity.MEDIUM, Confidence.LOW,
                               ValidationState.NEEDS_VALIDATION, kev=True)
    assert s >= 92
    assert any("KEV" in r for r in reasons)


def test_epss_lifts_score():
    base, _ = score_finding(Severity.MEDIUM, Confidence.HIGH, ValidationState.CONFIRMED)
    lifted, reasons = score_finding(Severity.MEDIUM, Confidence.HIGH,
                                    ValidationState.CONFIRMED, epss=0.9)
    assert lifted > base and lifted >= 90
    assert any("EPSS" in r for r in reasons)


def test_low_epss_does_not_lower():
    base, _ = score_finding(Severity.HIGH, Confidence.HIGH, ValidationState.CONFIRMED)
    with_low, _ = score_finding(Severity.HIGH, Confidence.HIGH,
                                ValidationState.CONFIRMED, epss=0.01)
    assert with_low == base            # tiny EPSS never reduces the score


def test_host_risk_takes_worst():
    from ..models import Finding, Host
    h = Host(ip="192.0.2.10")
    h.add_finding(Finding(title="a", asset="192.0.2.10:80", severity=Severity.LOW,
                          validation=ValidationState.OBSERVED))
    h.add_finding(Finding(title="b", asset="192.0.2.10:445", severity=Severity.HIGH,
                          validation=ValidationState.CONFIRMED))
    score, b = host_risk(h)
    hi, _ = score_finding(Severity.HIGH, Confidence.LOW, ValidationState.CONFIRMED)
    assert score == hi and b in ("high", "medium")


def _run_all():
    fns = [v for k, v in globals().items() if k.startswith("test_")]
    for fn in fns:
        fn()
        print(f"  ok  {fn.__name__}")
    print(f"\n{len(fns)}/{len(fns)} tests passed")


if __name__ == "__main__":
    _run_all()

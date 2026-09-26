"""Environmental risk scoring.

Fuses the signals netassess already collects into one explainable 0-100 score,
so findings are ranked by real-world urgency rather than raw severity alone:

  * base severity            (info -> critical)
  * exploitation reality     (CISA KEV -> near-max; FIRST EPSS -> probability lift)
  * evidence strength        (validation state + detection confidence)

Every score carries a written rationale, and nothing is asserted as high risk
without evidence to back it. This is pure analysis over existing findings — no
network activity.
"""
from __future__ import annotations

from .models import Confidence, Severity, ValidationState

# base score per severity (0-100 space)
_SEV_BASE = {
    Severity.CRITICAL: 90,
    Severity.HIGH: 70,
    Severity.MEDIUM: 45,
    Severity.LOW: 20,
    Severity.INFO: 5,
}

# unconfirmed findings are dampened (they're leads, not proof)
_VALIDATION_FACTOR = {
    ValidationState.CONFIRMED: 1.0,
    ValidationState.NEEDS_VALIDATION: 0.85,
    ValidationState.POTENTIAL: 0.85,
    ValidationState.OBSERVED: 0.9,
    ValidationState.FALSE_POSITIVE: 0.0,
}

_CONFIDENCE_FACTOR = {
    Confidence.HIGH: 1.0,
    Confidence.MEDIUM: 0.95,
    Confidence.LOW: 0.88,
}

# score -> band label
_BANDS = [(90, "critical"), (70, "high"), (40, "medium"), (10, "low"), (0, "info")]


def band(score: float) -> str:
    for threshold, label in _BANDS:
        if score >= threshold:
            return label
    return "info"


def score_finding(severity: Severity, confidence: Confidence,
                  validation: ValidationState, kev: bool = False,
                  epss: float | None = None) -> tuple[int, list[str]]:
    """Return (0-100 risk score, rationale lines) for one finding."""
    if validation == ValidationState.FALSE_POSITIVE:
        return 0, ["marked false positive"]

    base = _SEV_BASE.get(severity, 5)
    reasons = [f"severity {severity.value} (base {base})"]
    score = float(base)

    vf = _VALIDATION_FACTOR.get(validation, 0.9)
    if vf < 1.0:
        score *= vf
        reasons.append(f"unconfirmed ({validation.value}) x{vf}")

    cf = _CONFIDENCE_FACTOR.get(confidence, 0.95)
    if cf < 1.0:
        score *= cf
        reasons.append(f"{confidence.value} confidence x{cf}")

    # EPSS: exploitation probability lifts the score toward that likelihood
    if epss is not None:
        epss_pts = epss * 100.0
        if epss_pts > score:
            reasons.append(f"EPSS {epss:.0%} raises urgency")
            score = epss_pts

    # KEV: actively exploited in the wild -> near-max regardless of the rest
    if kev:
        reasons.append("ACTIVELY EXPLOITED (CISA KEV)")
        score = max(score, 92.0)

    return int(round(min(100.0, max(0.0, score)))), reasons


def host_risk(host) -> tuple[int, str]:
    """Host risk = the worst finding on it (0/'info' when it has none)."""
    best = 0
    for f in host.findings:
        s, _ = score_finding(f.severity, f.confidence, f.validation,
                             getattr(f, "kev", False), getattr(f, "epss", None))
        if s > best:
            best = s
    return best, band(best)

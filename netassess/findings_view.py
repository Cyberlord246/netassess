"""Findings view — severity filtering + cross-host aggregation for reports.

The raw asset graph keeps every finding (including info/low), so JSON export and
diffing stay complete. Human reports, however, should be signal-dense:

  * findings below a severity threshold (default MEDIUM) are suppressed, so
    noise like "missing security headers" (low) and "version disclosed" (info)
    stays out of the report;
  * the same issue seen on many hosts is collapsed into ONE entry that lists all
    affected assets, instead of repeating the finding per host.

This module is shared by the Markdown and HTML report generators.
"""
from __future__ import annotations

from dataclasses import dataclass, field

from .models import (
    CONFIDENCE_ORDER, Confidence, SEVERITY_ORDER, Severity, ValidationState,
)

_SEV_FROM_STR = {s.value: s for s in Severity}


def severity_from_str(value: str) -> Severity:
    return _SEV_FROM_STR.get((value or "").lower(), Severity.MEDIUM)


def at_least(sev: Severity, threshold: Severity) -> bool:
    return SEVERITY_ORDER[sev] >= SEVERITY_ORDER[threshold]


@dataclass
class AggFinding:
    title: str
    severity: Severity
    confidence: Confidence
    validation: ValidationState
    category: str
    source: str
    description: str
    why_it_matters: str
    impact: str
    remediation: str
    assets: list[str] = field(default_factory=list)
    # asset -> short evidence, so per-host specifics aren't lost on aggregation
    evidence_by_asset: dict[str, str] = field(default_factory=dict)
    kev: bool = False               # any merged instance is actively exploited
    epss: float | None = None       # max EPSS across merged instances

    @property
    def count(self) -> int:
        return len(self.assets)


@dataclass
class FindingsView:
    by_validation: dict[ValidationState, list[AggFinding]]
    kept: int
    suppressed: int
    threshold: Severity
    aggregated: bool
    severity_counts: dict[str, int]  # counts of KEPT findings by severity


def build_view(graph, min_severity: str = "medium",
               aggregate: bool = True) -> FindingsView:
    threshold = severity_from_str(min_severity)
    groups: dict[tuple, AggFinding] = {}
    kept = 0
    suppressed = 0
    sev_counts: dict[str, int] = {}

    for _host, f in graph.all_findings():
        if not at_least(f.severity, threshold):
            suppressed += 1
            continue
        kept += 1
        sev_counts[f.severity.value] = sev_counts.get(f.severity.value, 0) + 1

        if aggregate:
            key = (f.title, f.severity, f.validation, f.category, f.source)
        else:
            key = (f.title, f.asset, f.severity, f.validation)

        agg = groups.get(key)
        if agg is None:
            agg = AggFinding(
                title=f.title, severity=f.severity, confidence=f.confidence,
                validation=f.validation, category=f.category, source=f.source,
                description=f.description, why_it_matters=f.why_it_matters,
                impact=f.impact, remediation=f.remediation,
            )
            groups[key] = agg
        if f.asset not in agg.evidence_by_asset:
            agg.assets.append(f.asset)
            agg.evidence_by_asset[f.asset] = f.evidence
        # keep the strongest confidence seen across merged instances
        if CONFIDENCE_ORDER[f.confidence] > CONFIDENCE_ORDER[agg.confidence]:
            agg.confidence = f.confidence
        if getattr(f, "kev", False):
            agg.kev = True
        fe = getattr(f, "epss", None)
        if fe is not None and (agg.epss is None or fe > agg.epss):
            agg.epss = fe

    # bucket by validation state, most-severe first within each bucket
    by_val: dict[ValidationState, list[AggFinding]] = {}
    for agg in groups.values():
        agg.assets.sort(key=_asset_sort_key)
        by_val.setdefault(agg.validation, []).append(agg)
    for bucket in by_val.values():
        # actively-exploited (KEV) first, then severity, EPSS, host count
        bucket.sort(key=lambda a: (a.kev, SEVERITY_ORDER[a.severity],
                                   a.epss or 0.0, a.count),
                    reverse=True)

    return FindingsView(by_validation=by_val, kept=kept, suppressed=suppressed,
                        threshold=threshold, aggregated=aggregate,
                        severity_counts=sev_counts)


def _asset_sort_key(asset: str):
    ip, _, port = asset.partition(":")
    try:
        octets = tuple(int(x) for x in ip.split("."))
    except ValueError:
        octets = (0,)
    try:
        p = int(port)
    except ValueError:
        p = 0
    return (octets, p)

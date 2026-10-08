"""Additional report exports: CSV (spreadsheets) and SARIF 2.1.0 (CI / GitHub
code-scanning). Both operate on the full, unfiltered finding set so machine
consumers see everything; the human MD/HTML report keeps its severity floor.
"""
from __future__ import annotations

import csv
import io
import json
import re

from .models import Severity

# SARIF severity -> level
_LEVEL = {
    Severity.CRITICAL: "error", Severity.HIGH: "error",
    Severity.MEDIUM: "warning", Severity.LOW: "note", Severity.INFO: "note",
}


def _slug(s: str) -> str:
    return re.sub(r"[^a-z0-9]+", "-", (s or "").lower()).strip("-")[:60] or "finding"


def _rule_id(f) -> str:
    return (f.category or _slug(f.title)) if getattr(f, "category", "") else _slug(f.title)


def to_csv(graph) -> str:
    buf = io.StringIO()
    w = csv.writer(buf)
    w.writerow(["host", "asset", "title", "severity", "confidence",
                "validation", "category", "source", "kev", "epss", "evidence"])
    for host, f in graph.all_findings():
        w.writerow([
            host.ip,
            f.asset,
            f.title,
            f.severity.value,
            f.confidence.value,
            f.validation.value,
            getattr(f, "category", "") or "",
            getattr(f, "source", "") or "",
            "yes" if getattr(f, "kev", False) else "",
            (f"{f.epss:.4f}" if getattr(f, "epss", None) is not None else ""),
            (f.evidence or "").replace("\n", " ")[:500],
        ])
    return buf.getvalue()


def to_sarif(graph, tool_version: str = "1.0") -> str:
    rules: dict[str, dict] = {}
    results = []
    for host, f in graph.all_findings():
        rid = _rule_id(f)
        if rid not in rules:
            rules[rid] = {
                "id": rid,
                "name": _slug(f.title),
                "shortDescription": {"text": f.title[:120]},
                "fullDescription": {"text": (f.description or f.title)[:1000]},
                "defaultConfiguration": {"level": _LEVEL.get(f.severity, "note")},
                "properties": {"category": getattr(f, "category", "") or ""},
            }
        msg = f.title
        if f.evidence:
            msg += f" — {f.evidence}"
        results.append({
            "ruleId": rid,
            "level": _LEVEL.get(f.severity, "note"),
            "message": {"text": msg[:2000]},
            "locations": [{
                "physicalLocation": {
                    "artifactLocation": {"uri": f"netassess://{f.asset}"}},
                "logicalLocations": [{"fullyQualifiedName": f.asset,
                                      "name": host.ip}],
            }],
            "properties": {
                "severity": f.severity.value,
                "confidence": f.confidence.value,
                "validation": f.validation.value,
                "source": getattr(f, "source", "") or "",
                "kev": bool(getattr(f, "kev", False)),
                "epss": getattr(f, "epss", None),
            },
        })
    doc = {
        "version": "2.1.0",
        "$schema": "https://json.schemastore.org/sarif-2.1.0.json",
        "runs": [{
            "tool": {"driver": {
                "name": "netassess",
                "version": tool_version,
                "informationUri": "https://github.com/cyberlord246/netassess",
                "rules": list(rules.values()),
            }},
            "results": results,
        }],
    }
    return json.dumps(doc, indent=2)

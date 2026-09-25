"""Nuclei adapter — template-based detection when installed (light by default).

Runs ProjectDiscovery's `nuclei` against the web URLs netassess already
discovered (never a blind sweep), with a profile tuned to stay light on targets:

  * targeted input — only confirmed, in-scope URLs are fed in;
  * heavy template classes excluded (`dos,fuzzing,intrusive,brute-force,
    token-spray,headless`), keeping mostly one-request detections;
  * rate/concurrency caps, short timeout, single retry;
  * `-no-interactsh` (no external OOB callbacks) and `-duc` (no mid-run updates).

`--nuclei-thorough` relaxes the tag filter (still excludes dos/fuzzing/
intrusive/headless) and raises the rate. Results are normalized into the
platform's `Finding` schema; CVE templates carry their CVE id so KEV/EPSS
enrichment applies. Absent nuclei, the engine simply skips this phase.
"""
from __future__ import annotations

import json
import os
import tempfile
from urllib.parse import urlparse

from ..models import (
    Confidence, Finding, Severity, ValidationState,
)
from .base import ToolAdapter
from .process import ProcResult, run, which

_SEV = {"critical": Severity.CRITICAL, "high": Severity.HIGH,
        "medium": Severity.MEDIUM, "low": Severity.LOW, "info": Severity.INFO,
        "unknown": Severity.INFO}

# excluded in both profiles — these are what make nuclei "heavy"
_EXCLUDE_TAGS = "dos,fuzzing,intrusive,brute-force,token-spray,headless"
# included in the default light profile — lightweight detections
_LIGHT_TAGS = "exposures,misconfiguration,tech,ssl,cve,default-login,exposure"


class NucleiAdapter(ToolAdapter):
    name = "nuclei"

    def available(self) -> bool:
        return which("nuclei") is not None

    # -- command (unit-testable) ----------------------------------------- #
    def build_argv(self, targets_file: str, *, thorough: bool = False,
                   rate: int = 30, concurrency: int = 10, bulk: int = 10,
                   timeout: int = 5, severity: str = "low,medium,high,critical"
                   ) -> list[str]:
        argv = [
            "nuclei",
            "-l", targets_file,
            "-jsonl",                 # line-delimited JSON on stdout
            "-silent",
            "-duc",                   # disable update check
            "-no-interactsh",         # no external OOB callbacks
            "-rl", str(rate),
            "-c", str(concurrency),
            "-bs", str(bulk),
            "-timeout", str(timeout),
            "-retries", "1",
            "-severity", severity,
            "-exclude-tags", _EXCLUDE_TAGS,
        ]
        if not thorough:
            argv += ["-tags", _LIGHT_TAGS]     # restrict to light detections
        else:
            argv += ["-rl", str(max(rate, 60))]
        return argv

    # -- parsing --------------------------------------------------------- #
    def parse_jsonl(self, stdout: str) -> list[dict]:
        out = []
        for line in stdout.splitlines():
            line = line.strip()
            if not line.startswith("{"):
                continue
            try:
                out.append(json.loads(line))
            except json.JSONDecodeError:
                continue
        return out

    def _to_finding(self, obj: dict) -> Finding | None:
        info = obj.get("info", {}) or {}
        name = info.get("name") or obj.get("template-id") or "nuclei finding"
        sev = _SEV.get((info.get("severity") or "info").lower(), Severity.INFO)
        matched = obj.get("matched-at") or obj.get("host") or ""
        ip = obj.get("ip") or ""
        asset = self._asset(matched, ip)
        classification = info.get("classification") or {}
        cve_ids = classification.get("cve-id") or []
        if isinstance(cve_ids, str):
            cve_ids = [cve_ids]
        cvss = classification.get("cvss-score")
        refs = info.get("reference") or []
        if isinstance(refs, str):
            refs = [refs]
        tags = info.get("tags") or []
        if isinstance(tags, str):
            tags = [t.strip() for t in tags.split(",")]

        category = "known-vulnerability" if cve_ids else (
            tags[0] if tags else "nuclei")
        title = name
        if cve_ids:
            # put the CVE id in the title so KEV/EPSS enrichment can match it
            title = f"{cve_ids[0]}: {name}"
        evidence = f"nuclei [{obj.get('template-id','')}] matched at {matched}"
        if cvss:
            evidence += f"; CVSS {cvss}"
        extracted = obj.get("extracted-results")
        if extracted:
            evidence += f"; extracted={extracted[:3]}"

        return Finding(
            title=title, asset=asset,
            evidence=evidence,
            description=(info.get("description") or "").strip()[:500],
            why_it_matters="Detected by a nuclei community template.",
            severity=sev, confidence=Confidence.HIGH,
            impact=(f"See {', '.join(cve_ids)}." if cve_ids else
                    "Confirmed by template match; review exposure."),
            remediation=("References: " + " ".join(refs[:3])) if refs else
                        "Review the matched template and remediate the exposure.",
            validation=ValidationState.CONFIRMED,
            source="nuclei", category=f"nuclei-{category}"[:40],
        )

    def _asset(self, matched: str, ip: str) -> str:
        try:
            u = urlparse(matched if "://" in matched else "http://" + matched)
            port = u.port or (443 if u.scheme == "https" else 80)
            host = ip or u.hostname or matched
            return f"{host}:{port}"
        except ValueError:
            return ip or matched or "unknown"

    # -- run over a set of URLs ------------------------------------------ #
    def scan(self, urls: list[str], *, thorough: bool = False,
             rate: int = 30, run_timeout: float = 900.0
             ) -> tuple[list[Finding], ProcResult]:
        if not urls:
            return [], ProcResult(True, 0, "", "")
        tf = tempfile.NamedTemporaryFile("w", suffix=".txt", delete=False,
                                         encoding="utf-8")
        try:
            tf.write("\n".join(urls))
            tf.close()
            argv = self.build_argv(tf.name, thorough=thorough, rate=rate)
            res = run(argv, timeout=run_timeout)
        finally:
            try:
                os.unlink(tf.name)
            except OSError:
                pass
        findings = []
        for obj in self.parse_jsonl(res.stdout):
            f = self._to_finding(obj)
            if f is not None:
                findings.append(f)
        return findings, res

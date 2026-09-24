"""Optional live CVE enrichment via the NVD 2.0 API.

Disabled by default. Enable with ``--cve-online``. This is the ONLY component
that reaches a third-party service, and it sends only product/version keywords
(never target identities beyond that). It is best-effort: any network/parse
error is swallowed and the offline KB results stand on their own.

NVD enforces rate limits (roughly 5 requests / 30s without an API key), so this
adapter caches per product+version and paces requests. Set NVD_API_KEY in the
environment for a higher limit.
"""
from __future__ import annotations

import json
import os
import threading
import time
import urllib.parse
import urllib.request

from ..models import Confidence, Finding, Host, Port, Severity, ValidationState

_NVD_URL = "https://services.nvd.nist.gov/rest/json/cves/2.0"
_SEV_MAP = {
    "CRITICAL": Severity.CRITICAL, "HIGH": Severity.HIGH,
    "MEDIUM": Severity.MEDIUM, "LOW": Severity.LOW, "NONE": Severity.INFO,
}


class NVDOnlineAdapter:
    def __init__(self, timeout: float = 10.0, max_per_query: int = 5,
                 min_interval: float = 6.0):
        self.timeout = timeout
        self.max_per_query = max_per_query
        self.min_interval = min_interval if not os.environ.get("NVD_API_KEY") else 0.7
        self._cache: dict[str, list[dict]] = {}
        self._last = 0.0
        self._lock = threading.Lock()

    def available(self) -> bool:
        return True  # network availability is checked at call time

    def _throttle(self):
        with self._lock:
            wait = self.min_interval - (time.monotonic() - self._last)
            if wait > 0:
                time.sleep(wait)
            self._last = time.monotonic()

    def _query(self, keyword: str) -> list[dict]:
        if keyword in self._cache:
            return self._cache[keyword]
        self._throttle()
        params = urllib.parse.urlencode({
            "keywordSearch": keyword,
            "resultsPerPage": self.max_per_query,
        })
        req = urllib.request.Request(f"{_NVD_URL}?{params}",
                                     headers={"User-Agent": "netassess/1.0"})
        api_key = os.environ.get("NVD_API_KEY")
        if api_key:
            req.add_header("apiKey", api_key)
        try:
            with urllib.request.urlopen(req, timeout=self.timeout) as resp:
                data = json.loads(resp.read().decode("utf-8", "replace"))
        except Exception:
            self._cache[keyword] = []
            return []
        out = self._parse(data)
        self._cache[keyword] = out
        return out

    def _parse(self, data: dict) -> list[dict]:
        results = []
        for item in data.get("vulnerabilities", [])[: self.max_per_query]:
            cve = item.get("cve", {})
            cid = cve.get("id", "")
            descs = cve.get("descriptions", [])
            summary = next((d["value"] for d in descs if d.get("lang") == "en"), "")
            sev, score = "MEDIUM", None
            metrics = cve.get("metrics", {})
            for key in ("cvssMetricV31", "cvssMetricV30", "cvssMetricV2"):
                if metrics.get(key):
                    m = metrics[key][0]
                    cvss = m.get("cvssData", {})
                    score = cvss.get("baseScore")
                    sev = (m.get("baseSeverity") or cvss.get("baseSeverity")
                           or "MEDIUM").upper()
                    break
            results.append({"id": cid, "summary": summary, "severity": sev,
                            "cvss": score})
        return results

    def enrich(self, host: Host, port: Port, candidates) -> list[Finding]:
        asset = f"{host.ip}:{port.number}"
        findings: list[Finding] = []
        seen: set[str] = set()
        for product_text, version, evidence in candidates:
            product = product_text.strip().split()[0] if product_text.strip() else ""
            if not product or not version:
                continue
            for rec in self._query(f"{product} {version}"):
                if not rec["id"] or rec["id"] in seen:
                    continue
                seen.add(rec["id"])
                sev = _SEV_MAP.get(rec["severity"], Severity.MEDIUM)
                findings.append(Finding(
                    title=f"{rec['id']} (NVD): {product} {version}",
                    asset=asset,
                    evidence=f"{evidence}; NVD keyword match"
                             + (f"; CVSS {rec['cvss']}" if rec["cvss"] else ""),
                    description=rec["summary"][:500],
                    why_it_matters="NVD lists this CVE for the observed product/version keyword.",
                    severity=sev, confidence=Confidence.LOW,
                    impact=f"See {rec['id']} on NVD. Keyword match — verify applicability.",
                    remediation=f"Review https://nvd.nist.gov/vuln/detail/{rec['id']} "
                                "and patch if applicable.",
                    validation=ValidationState.NEEDS_VALIDATION,
                    source="cve-nvd", category="known-vulnerability",
                ))
        return findings

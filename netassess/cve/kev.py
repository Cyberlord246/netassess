"""CISA KEV + FIRST EPSS enrichment.

Adds exploitation intelligence to CVE findings without touching targets:

  * **CISA KEV** — the Known Exploited Vulnerabilities catalog: CVEs confirmed
    *exploited in the wild*. A KEV hit is a strong "fix this now" signal.
  * **EPSS** — FIRST's Exploit Prediction Scoring System: probability (0..1) a
    CVE will be exploited in the next 30 days.

Data is fetched from CISA/FIRST (not your targets) by ``netassess kev sync`` and
cached locally; enrichment then runs fully offline over findings you already
have. Enrichment raises severity/priority for actively-exploited issues and
annotates each finding.
"""
from __future__ import annotations

import csv
import gzip
import io
import json
import os
import re
import time
import urllib.request

from ..models import Finding, Severity

_KEV_URL = ("https://www.cisa.gov/sites/default/files/feeds/"
            "known_exploited_vulnerabilities.json")
_EPSS_URL = "https://epss.cyentia.com/epss_scores-current.csv.gz"
_CVE_RE = re.compile(r"CVE-\d{4}-\d{4,}", re.I)


def default_cache_path() -> str:
    return os.path.join(os.path.expanduser("~"), ".netassess", "kev.json")


def cve_in(text: str) -> str | None:
    m = _CVE_RE.search(text or "")
    return m.group(0).upper() if m else None


# --------------------------------------------------------------------------- #
# sync
# --------------------------------------------------------------------------- #
class KEVSync:
    def __init__(self, timeout: float = 60.0):
        self.timeout = timeout

    def _fetch(self, url: str) -> bytes | None:
        req = urllib.request.Request(url, headers={"User-Agent": "netassess/1.0"})
        try:
            with urllib.request.urlopen(req, timeout=self.timeout) as resp:
                return resp.read()
        except Exception:
            return None

    def fetch_kev(self, log=lambda *a: None) -> dict:
        raw = self._fetch(_KEV_URL)
        if not raw:
            log("    ! KEV download failed")
            return {}
        try:
            data = json.loads(raw.decode("utf-8", "replace"))
        except json.JSONDecodeError:
            return {}
        out = {}
        for v in data.get("vulnerabilities", []):
            cid = (v.get("cveID") or "").upper()
            if cid:
                out[cid] = {
                    "dateAdded": v.get("dateAdded", ""),
                    "name": v.get("vulnerabilityName", ""),
                    "ransomware": (v.get("knownRansomwareCampaignUse", "")
                                   .lower() == "known"),
                }
        return out

    def fetch_epss(self, log=lambda *a: None) -> dict:
        raw = self._fetch(_EPSS_URL)
        if not raw:
            log("    ! EPSS download failed")
            return {}
        try:
            text = gzip.decompress(raw).decode("utf-8", "replace")
        except OSError:
            text = raw.decode("utf-8", "replace")
        scores = {}
        for row in csv.reader(io.StringIO(text)):
            if not row or row[0].startswith("#") or row[0].lower() == "cve":
                continue
            try:
                scores[row[0].upper()] = float(row[1])
            except (IndexError, ValueError):
                continue
        return scores

    def sync(self, out_path: str | None = None, log=print) -> dict:
        out_path = out_path or default_cache_path()
        log("[kev-sync] downloading CISA KEV catalog…")
        kev = self.fetch_kev(log)
        log(f"      {len(kev)} known-exploited CVE(s)")
        log("[kev-sync] downloading FIRST EPSS scores…")
        epss = self.fetch_epss(log)
        log(f"      {len(epss)} EPSS score(s)")
        payload = {
            "synced": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
            "kev": kev, "epss": epss,
        }
        os.makedirs(os.path.dirname(os.path.abspath(out_path)), exist_ok=True)
        tmp = out_path + ".tmp"
        with open(tmp, "w", encoding="utf-8") as fh:
            json.dump(payload, fh)
        os.replace(tmp, out_path)
        log(f"[kev-sync] wrote cache -> {out_path}")
        return {"kev": len(kev), "epss": len(epss), "path": out_path}


# --------------------------------------------------------------------------- #
# data + enrichment
# --------------------------------------------------------------------------- #
class KEVData:
    def __init__(self, kev: dict | None = None, epss: dict | None = None):
        self.kev = kev or {}
        self.epss = epss or {}

    @classmethod
    def load(cls, path: str) -> "KEVData":
        try:
            with open(path, "r", encoding="utf-8") as fh:
                d = json.load(fh)
            return cls(d.get("kev", {}), d.get("epss", {}))
        except (OSError, json.JSONDecodeError):
            return cls()

    @property
    def available(self) -> bool:
        return bool(self.kev or self.epss)

    def enrich_finding(self, f: Finding) -> bool:
        """Annotate one finding in place. Returns True if anything changed."""
        cid = cve_in(f.title) or cve_in(f.evidence)
        if not cid:
            return False
        changed = False
        score = self.epss.get(cid)
        if score is not None and f.epss is None:
            f.epss = score
            f.evidence = (f.evidence + f" | EPSS {score:.2%}").strip(" |")
            changed = True
        info = self.kev.get(cid)
        if info and not f.kev:
            f.kev = True
            tag = "actively exploited — CISA KEV"
            if info.get("ransomware"):
                tag += " (ransomware)"
            f.evidence = f"[{tag}] " + f.evidence
            f.why_it_matters = ("This CVE is on CISA's Known Exploited "
                                "Vulnerabilities list — exploited in the wild. "
                                + f.why_it_matters)
            # actively-exploited issues are at least HIGH (CRITICAL if ransomware)
            floor = Severity.CRITICAL if info.get("ransomware") else Severity.HIGH
            from ..models import SEVERITY_ORDER
            if SEVERITY_ORDER[f.severity] < SEVERITY_ORDER[floor]:
                f.severity = floor
            changed = True
        return changed


def enrich_graph(graph, data: KEVData) -> dict:
    """Enrich all findings in the graph. Returns counts."""
    kev_hits = 0
    epss_scored = 0
    for host in graph.hosts.values():
        for f in host.findings:
            before_kev, before_epss = f.kev, f.epss
            data.enrich_finding(f)
            if f.kev and not before_kev:
                kev_hits += 1
            if f.epss is not None and before_epss is None:
                epss_scored += 1
    return {"kev": kev_hits, "epss": epss_scored}

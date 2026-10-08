"""CVE correlation engine.

Extracts (product, version) evidence already collected in the asset graph
(service product/version, banners, HTTP Server headers, detected technologies)
and matches it against the offline CVE knowledge base. Optionally enriches with
a live source (NVD) when explicitly enabled.

Findings are emitted as NEEDS_VALIDATION (POTENTIAL confidence) because a
version string is a lead, not proof — back-ports and disabled features routinely
make a "matching" version not actually exploitable.
"""
from __future__ import annotations

import re

from ..models import (
    Confidence, Finding, Host, Port, Severity, ValidationState,
)
import os

from ..state import AssetGraph
from .database import load_db, load_cache_file
from .nvd_sync import default_cache_path
from .version import in_range, parse_version

_SEV_MAP = {
    "critical": Severity.CRITICAL, "high": Severity.HIGH,
    "medium": Severity.MEDIUM, "low": Severity.LOW, "info": Severity.INFO,
}

# pull "name/version" or "name X.Y.Z" out of a free-form string
_VER_TOKEN = re.compile(r"([A-Za-z][A-Za-z0-9_+.-]*?)[/ _-]v?(\d+(?:\.\d+)+[a-z]?(?:p\d+)?)")


class CVEEngine:
    def __init__(self, config, online_adapter=None):
        self.config = config
        db = load_db(getattr(config, "cve_db", None))
        # merge the offline NVD sync cache if present (default ~/.netassess/nvd.json)
        cache = getattr(config, "cve_nvd_cache", None) or default_cache_path()
        self.nvd_cache_loaded = 0
        if os.path.isfile(cache):
            extra = load_cache_file(cache)
            db.extend(extra)
            self.nvd_cache_loaded = len(extra)
        self.db = db
        self.online = online_adapter

    # -- evidence extraction --------------------------------------------- #
    def _candidates(self, host: Host, port: Port) -> list[tuple[str, str, str]]:
        """Return list of (product_text, version, evidence) for one port."""
        out: list[tuple[str, str, str]] = []
        svc = port.service

        if svc.version and (svc.product or svc.name):
            out.append((f"{svc.product} {svc.name}".strip(), svc.version,
                        f"service detection: {svc.product} {svc.version}".strip()))
        # extract from banner / product string
        blob = " ".join(x for x in (svc.product, svc.banner) if x)
        for m in _VER_TOKEN.finditer(blob):
            out.append((m.group(1), m.group(2), f"banner: {m.group(0)}"))

        # HTTP evidence for this port
        for hs in host.http_services:
            if hs.port != port.number:
                continue
            if hs.server:
                for m in _VER_TOKEN.finditer(hs.server):
                    out.append((m.group(1), m.group(2),
                                f"Server header: {hs.server}"))
            for tech in hs.technologies:
                if tech.version:
                    out.append((tech.name, tech.version,
                                f"technology: {tech.name}/{tech.version}"))
        return out

    # -- matching --------------------------------------------------------- #
    @staticmethod
    def _kw_match(kw: str, text: str) -> bool:
        """Word-boundary (CPE-style token) match: 'ssl' matches 'openssl 1.0.1'
        but NOT 'wassl'; 'ftp' does not match 'sftp'. A trailing digit/dot is
        allowed so a version glued to the product ('openssl1.0.1f') still hits."""
        kw = kw.lower().strip()
        if not kw:
            return False
        return re.search(r"(?<![a-z0-9])" + re.escape(kw) + r"(?![a-z])", text) \
            is not None

    def _entry_keywords(self, entry: dict) -> list[str]:
        kws = list(entry.get("keywords", []))
        # derive vendor/product tokens from a CPE 2.3 string if present
        cpe = entry.get("cpe", "")
        parts = cpe.split(":") if cpe else []
        if len(parts) >= 5:
            for field in (parts[3], parts[4]):            # vendor, product
                kws += [t for t in field.replace("_", " ").split() if t]
        return kws

    def _match_entry(self, product_text: str, version: str, entry: dict) -> bool:
        low = product_text.lower()
        # precision: an excluded token (e.g. 'tomcat' for an apache httpd CVE)
        # vetoes the match outright — kills same-vendor-different-product FPs.
        if any(self._kw_match(ex, low) for ex in entry.get("exclude_keywords", [])):
            return False
        if not any(self._kw_match(kw, low) for kw in self._entry_keywords(entry)):
            return False
        if parse_version(version) is None:
            return False
        for rng in entry.get("ranges", []):
            if in_range(version, rng.get("introduced"), rng.get("fixed"),
                        rng.get("last_affected")):
                return True
        return False

    def assess_port(self, host: Host, port: Port) -> list[Finding]:
        asset = f"{host.ip}:{port.number}"
        findings: list[Finding] = []
        seen_ids: set[str] = set()
        for product_text, version, evidence in self._candidates(host, port):
            for entry in self.db:
                if entry["id"] in seen_ids:
                    continue
                if self._match_entry(product_text, version, entry):
                    seen_ids.add(entry["id"])
                    findings.append(self._to_finding(asset, version, evidence, entry))
        # optional online enrichment
        if self.online is not None:
            try:
                findings.extend(self.online.enrich(host, port, self._candidates(host, port)))
            except Exception:
                pass
        return findings

    def _to_finding(self, asset: str, version: str, evidence: str, entry: dict) -> Finding:
        sev = _SEV_MAP.get(entry.get("severity", "medium"), Severity.MEDIUM)
        refs = " ".join(entry.get("references", []))
        cvss = entry.get("cvss")
        return Finding(
            title=f"{entry['id']}: {entry.get('product','')}".strip(),
            asset=asset,
            evidence=f"{evidence}; matched version {version}"
                     + (f"; CVSS {cvss}" if cvss else ""),
            description=entry.get("summary", ""),
            why_it_matters="The observed version falls within a range affected by "
                           "a published vulnerability.",
            severity=sev, confidence=Confidence.MEDIUM,
            impact=f"See {entry['id']}. Exploitability depends on configuration and "
                   "whether the vendor back-ported a fix.",
            remediation=f"Confirm the exact build/patch level; update to a fixed "
                        f"release. References: {refs}",
            validation=ValidationState.NEEDS_VALIDATION,
            source="cve-kb", category="known-vulnerability",
        )

    def assess(self, graph: AssetGraph) -> int:
        added = 0
        for host in graph.hosts.values():
            for port in host.open_ports():
                for finding in self.assess_port(host, port):
                    before = len(host.findings)
                    host.add_finding(finding)
                    if len(host.findings) > before:
                        added += 1
        return added

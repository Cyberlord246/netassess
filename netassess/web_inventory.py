"""Web attack-surface inventory — correlation + deduplication over the graph.

Turns the raw per-service HTTP results already collected by the pipeline into a
clean, correlated inventory of distinct web *applications*. This is pure analysis
over the asset graph — it starts no new scans and reuses the data that the HTTP
probe, content discovery, vhost discovery, tech detection, CVE/validation and
risk scoring have already produced.

Deduplication key = the response fingerprint (techdetect.response_fingerprint),
so the same application served under many hostnames / IPs collapses into ONE
asset that lists every exposure, instead of N near-identical entries. Genuinely
different applications (different fingerprint) are never merged, even on a shared
IP.

Each WebAsset ties together: hostnames, IPs, port, scheme, status/title/server,
technologies, CDN/WAF, TLS SANs, vhosts, discovered endpoints (categorised +
interesting), and the related findings split into misconfiguration /
information-leakage / vulnerability-candidate buckets, with the strongest
validation state and the highest risk score attached.
"""
from __future__ import annotations

import ipaddress
import re
from dataclasses import dataclass, field
from typing import Optional
from urllib.parse import urlparse

from .findings_view import VALIDATION_RANK
from .models import Severity, ValidationState
from .risk import band, score_finding

# categories that are "interesting" endpoints (not generic grouped noise)
from .content_discovery import GROUPED_CATEGORIES

_MISCONFIG_CATEGORIES = {"http-config", "http-misconfig", "misconfiguration",
                         "tls", "tls-config", "vhost-discovery"}
_INFOLEAK_HINTS = ("leak", "disclosure", "info-leak", "information")
_ASSET_RE = re.compile(r"^([0-9a-fA-F:.]+):(\d+)(?:\s+\[(.+)\])?$")


def _is_ip(v: str) -> bool:
    try:
        ipaddress.ip_address(v)
        return True
    except ValueError:
        return False


def _parse_asset(asset: str):
    """'ip:port' or 'ip:port [vhost]' -> (ip, port, vhost|'')."""
    m = _ASSET_RE.match(asset.strip())
    if not m:
        ip, _, port = asset.partition(":")
        return ip, port, ""
    return m.group(1), m.group(2), (m.group(3) or "")


@dataclass
class Exposure:
    url: str
    scheme: str
    ip: str
    port: int
    hostname: str          # the name it's served under (vhost/host), or the IP


@dataclass
class WebAsset:
    fingerprint: str
    name: str = ""
    scheme: str = ""
    status: Optional[int] = None
    title: str = ""
    server: str = ""
    technologies: list[str] = field(default_factory=list)
    cdn: str = ""
    waf: str = ""
    exposures: list[Exposure] = field(default_factory=list)
    ips: set = field(default_factory=set)
    hostnames: set = field(default_factory=set)
    tls_sans: set = field(default_factory=set)
    vhosts: set = field(default_factory=set)
    endpoints: list[dict] = field(default_factory=list)
    endpoint_categories: dict = field(default_factory=dict)
    interesting_endpoints: list[str] = field(default_factory=list)
    misconfigurations: list[str] = field(default_factory=list)
    info_leaks: list[str] = field(default_factory=list)
    vuln_candidates: list[str] = field(default_factory=list)
    other_findings: list[str] = field(default_factory=list)
    validation: ValidationState = ValidationState.OBSERVED
    risk: int = 0
    risk_band: str = "info"

    @property
    def exposure_count(self) -> int:
        return len(self.exposures)


def build_inventory(graph) -> list[WebAsset]:
    # index findings by (ip, port) so we can correlate them to each exposure
    findings_by_hostport: dict[tuple, list] = {}
    for host in graph.hosts.values():
        for f in host.findings:
            ip, port, tag = _parse_asset(f.asset)
            findings_by_hostport.setdefault((ip, port), []).append((f, tag))

    groups: dict[str, WebAsset] = {}
    for host in graph.hosts.values():
        for svc in host.http_services:
            key = svc.fingerprint or f"{svc.ip}:{svc.port}:{svc.url}"
            asset = groups.get(key)
            if asset is None:
                asset = WebAsset(fingerprint=svc.fingerprint, scheme=svc.scheme,
                                 status=svc.status, title=svc.title,
                                 server=svc.server, cdn=svc.cdn, waf=svc.waf)
                asset.technologies = [
                    f"{t.name}{('/' + t.version) if t.version else ''}"
                    for t in svc.technologies]
                groups[key] = asset

            hostname = urlparse(svc.url).hostname or svc.ip
            asset.exposures.append(Exposure(
                url=svc.url, scheme=svc.scheme, ip=svc.ip, port=svc.port,
                hostname=hostname))
            asset.ips.add(svc.ip)
            if hostname and not _is_ip(hostname):
                asset.hostnames.add(hostname)
                if hostname != (host.hostnames[0] if host.hostnames else None):
                    asset.vhosts.add(hostname)
            for hn in host.hostnames:
                asset.hostnames.add(hn)
            # TLS SANs from the service or the host's cert on that port
            for tls in (svc.tls, host.tls.get(svc.port)):
                if tls:
                    asset.tls_sans.update(tls.sans or [])
            if not asset.cdn and svc.cdn:
                asset.cdn = svc.cdn
            if not asset.waf and svc.waf:
                asset.waf = svc.waf

            _merge_endpoints(asset, svc)
            _correlate_findings(asset, svc, host, findings_by_hostport)

    # finalise: choose a display name, compute risk/validation, prioritise
    assets = list(groups.values())
    for a in assets:
        _finalise(a)
    assets.sort(key=lambda a: (a.risk, len(a.vuln_candidates),
                               len(a.misconfigurations), a.exposure_count),
                reverse=True)
    return assets


def _merge_endpoints(asset: WebAsset, svc) -> None:
    seen = {(e["path"], e.get("status")) for e in asset.endpoints}
    for d in svc.discovered_paths or []:
        k = (d.get("path"), d.get("status"))
        if k in seen:
            continue
        seen.add(k)
        asset.endpoints.append(d)
        cat = d.get("category", "other")
        asset.endpoint_categories[cat] = asset.endpoint_categories.get(cat, 0) + 1
        # "interesting" = a high-value (non-generic) category
        if cat not in GROUPED_CATEGORIES and d.get("path"):
            if d["path"] not in asset.interesting_endpoints:
                asset.interesting_endpoints.append(d["path"])


def _correlate_findings(asset: WebAsset, svc, host, index) -> None:
    for f, tag in index.get((svc.ip, str(svc.port)), []):
        # a vhost-tagged finding belongs only to an asset served under that name
        if tag and tag not in asset.hostnames and tag not in asset.vhosts:
            continue
        title = f.title
        cat = (f.category or "").lower()
        if cat == "known-vulnerability":
            _add_unique(asset.vuln_candidates, title)
        elif any(h in cat or h in title.lower() for h in _INFOLEAK_HINTS):
            _add_unique(asset.info_leaks, title)
        elif cat in _MISCONFIG_CATEGORIES or cat.startswith("http"):
            _add_unique(asset.misconfigurations, title)
        elif cat.startswith("content") or cat in ("common", "dir", "secrets",
                                                   "config", "admin", "api"):
            pass    # already represented via endpoints
        else:
            _add_unique(asset.other_findings, title)

        # strongest validation + highest risk across correlated findings
        if VALIDATION_RANK.get(f.validation, 0) > VALIDATION_RANK.get(asset.validation, 0):
            asset.validation = f.validation
        s, _ = score_finding(f.severity, f.confidence, f.validation,
                             getattr(f, "kev", False), getattr(f, "epss", None))
        if s > asset.risk:
            asset.risk = s


def _finalise(a: WebAsset) -> None:
    a.risk_band = band(a.risk)
    a.technologies = sorted(set(a.technologies))
    a.interesting_endpoints = sorted(set(a.interesting_endpoints))
    a.tls_sans = set(sorted(a.tls_sans))
    # display name: prefer a real hostname over a bare IP
    if a.hostnames:
        a.name = sorted(a.hostnames)[0]
    else:
        ex = a.exposures[0] if a.exposures else None
        a.name = f"{ex.ip}:{ex.port}" if ex else "(unknown)"


def _add_unique(seq: list, item: str) -> None:
    if item and item not in seq:
        seq.append(item)


def inventory_summary(assets: list[WebAsset]) -> dict:
    """Headline numbers for the report."""
    total_exposures = sum(a.exposure_count for a in assets)
    return {
        "apps": len(assets),
        "exposures": total_exposures,
        "deduped": max(0, total_exposures - len(assets)),
        "with_vulns": sum(1 for a in assets if a.vuln_candidates),
        "with_misconfig": sum(1 for a in assets if a.misconfigurations),
        "behind_cdn": sum(1 for a in assets if a.cdn),
        "behind_waf": sum(1 for a in assets if a.waf),
    }

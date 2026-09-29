"""Tests for the web attack-surface inventory (correlation + deduplication).

Run: python -m netassess.tests.test_web_inventory
"""
from __future__ import annotations

from ..models import (
    Confidence, Finding, Host, HTTPService, Port, PortState, Service, Severity,
    Technology, TLSInfo, ValidationState,
)
from ..state import AssetGraph
from ..techdetect import cdn_of, response_fingerprint, waf_of
from ..web_inventory import build_inventory, inventory_summary


def _svc(url, ip="10.0.0.5", port=443, title="Acme", server="nginx/1.18.0",
         clen=5120, techs=None, cdn="", waf="", paths=None, tls=None):
    s = HTTPService(url=url, ip=ip, port=port, scheme="https", status=200,
                    title=title, server=server, content_length=clen)
    s.technologies = techs or [Technology(name="nginx", version="1.18.0",
                                          category="web-server")]
    s.cdn, s.waf = cdn, waf
    s.discovered_paths = paths or []
    s.tls = tls
    s.fingerprint = response_fingerprint(s)
    return s


def _graph(*svcs, hostnames=None, findings=None):
    g = AssetGraph()
    h = g.get_or_create("10.0.0.5")
    h.hostnames = hostnames or []
    h.ports[443] = Port(number=443, state=PortState.OPEN,
                        service=Service(name="https"))
    h.http_services = list(svcs)
    h.findings = findings or []
    return g


def test_same_app_across_hostnames_is_deduplicated():
    g = _graph(_svc("https://app.example.com:443/"),
               _svc("https://www.example.com:443/"))
    assets = build_inventory(g)
    assert len(assets) == 1                      # one app, two exposures
    a = assets[0]
    assert a.exposure_count == 2
    assert {"app.example.com", "www.example.com"} <= a.hostnames


def test_different_apps_on_same_ip_stay_separate():
    g = _graph(_svc("https://app.example.com:443/", title="Dashboard", clen=5000),
               _svc("https://admin.example.com:443/", title="Admin Console", clen=9000))
    assets = build_inventory(g)
    assert len(assets) == 2                      # distinct fingerprints not merged
    summ = inventory_summary(assets)
    assert summ["apps"] == 2 and summ["deduped"] == 0


def test_interesting_endpoints_extracted_generic_ignored():
    paths = [
        {"path": "/.git/config", "url": "u", "status": 200, "category": "secrets"},
        {"path": "/admin", "url": "u", "status": 401, "category": "admin"},
        {"path": "/index.html", "url": "u", "status": 200, "category": "common"},
    ]
    g = _graph(_svc("https://app.example.com:443/", paths=paths))
    a = build_inventory(g)[0]
    assert "/.git/config" in a.interesting_endpoints
    assert "/admin" in a.interesting_endpoints
    assert "/index.html" not in a.interesting_endpoints      # generic
    assert a.endpoint_categories.get("common") == 1


def test_cdn_and_waf_surfaced():
    g = _graph(_svc("https://app.example.com:443/", cdn="Cloudflare",
                    waf="Imperva Incapsula"))
    a = build_inventory(g)[0]
    assert a.cdn == "Cloudflare" and a.waf == "Imperva Incapsula"
    assert inventory_summary([a])["behind_cdn"] == 1


def test_findings_correlated_into_buckets():
    fs = [
        Finding(title="CVE-2021-23017: nginx", asset="10.0.0.5:443",
                severity=Severity.HIGH, confidence=Confidence.MEDIUM,
                validation=ValidationState.NEEDS_VALIDATION,
                source="cve-kb", category="known-vulnerability"),
        Finding(title="Directory listing enabled", asset="10.0.0.5:443",
                severity=Severity.MEDIUM, validation=ValidationState.CONFIRMED,
                source="http-probe", category="http-misconfig"),
    ]
    g = _graph(_svc("https://app.example.com:443/"), findings=fs)
    a = build_inventory(g)[0]
    assert "CVE-2021-23017: nginx" in a.vuln_candidates
    assert "Directory listing enabled" in a.misconfigurations
    assert a.risk > 0
    assert a.validation == ValidationState.CONFIRMED     # strongest state wins


def test_vhost_tagged_finding_only_attaches_to_that_app():
    # two different apps on same ip:port; a tagged finding must hit only its vhost
    g = _graph(_svc("https://app.example.com:443/", title="Dashboard", clen=5000),
               _svc("https://admin.example.com:443/", title="Admin", clen=9000),
               findings=[Finding(title="Directory listing (admin)",
                                 asset="10.0.0.5:443 [admin.example.com]",
                                 severity=Severity.MEDIUM, source="http-probe",
                                 category="http-misconfig")])
    assets = {a.name: a for a in build_inventory(g)}
    admin, other = assets["admin.example.com"], assets["app.example.com"]
    assert "Directory listing (admin)" in admin.misconfigurations   # matched vhost
    assert "Directory listing (admin)" not in other.misconfigurations  # not the other


def test_techdetect_helpers():
    assert waf_of({"CF-RAY": "abc123"}) == "Cloudflare"
    assert waf_of({"Set-Cookie": "incap_ses_123=x"}) == "Imperva Incapsula"
    assert waf_of({"X-Foo": "bar"}) == ""
    techs = [Technology(name="Cloudflare", category="cdn"),
             Technology(name="PHP", category="language")]
    assert cdn_of(techs) == "Cloudflare"
    # fingerprint stable for identical responses, differs on title
    s1 = _svc("https://a/"); s2 = _svc("https://b/")
    s3 = _svc("https://c/", title="Different")
    assert s1.fingerprint == s2.fingerprint
    assert s1.fingerprint != s3.fingerprint


def _run_all():
    fns = [v for k, v in sorted(globals().items()) if k.startswith("test_")]
    for fn in fns:
        fn()
        print(f"  ok  {fn.__name__}")
    print(f"\n{len(fns)}/{len(fns)} tests passed")


if __name__ == "__main__":
    _run_all()

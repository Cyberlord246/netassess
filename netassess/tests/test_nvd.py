"""Tests for the offline NVD sync parser (no network).

Run: python -m netassess.tests.test_nvd
"""
from __future__ import annotations

from ..cve.nvd_sync import merge_entries, parse_response

# A trimmed NVD 2.0 API response shaped like the real thing.
_SAMPLE = {
    "vulnerabilities": [
        {"cve": {
            "id": "CVE-2021-41773",
            "descriptions": [{"lang": "en", "value": "Path traversal in Apache 2.4.49"}],
            "metrics": {"cvssMetricV31": [{"cvssData": {"baseScore": 7.5,
                                                        "baseSeverity": "HIGH"},
                                           "baseSeverity": "HIGH"}]},
            "configurations": [{"nodes": [{"cpeMatch": [
                {"vulnerable": True,
                 "criteria": "cpe:2.3:a:apache:http_server:2.4.49:*:*:*:*:*:*:*"}
            ]}]}],
            "references": [{"url": "https://nvd.nist.gov/vuln/detail/CVE-2021-41773"}],
        }},
        {"cve": {
            "id": "CVE-2021-44224",
            "descriptions": [{"lang": "en", "value": "SSRF/crash in Apache httpd"}],
            "metrics": {"cvssMetricV31": [{"cvssData": {"baseScore": 8.2},
                                           "baseSeverity": "HIGH"}]},
            "configurations": [{"nodes": [{"cpeMatch": [
                {"vulnerable": True,
                 "criteria": "cpe:2.3:a:apache:http_server:*:*:*:*:*:*:*:*",
                 "versionStartIncluding": "2.4.7",
                 "versionEndIncluding": "2.4.51"}
            ]}]}],
            "references": [],
        }},
        {"cve": {   # unrelated product in same config -> must be ignored
            "id": "CVE-9999-0000",
            "descriptions": [{"lang": "en", "value": "not apache"}],
            "metrics": {},
            "configurations": [{"nodes": [{"cpeMatch": [
                {"vulnerable": True,
                 "criteria": "cpe:2.3:a:someone:otherproduct:1.0:*:*:*:*:*:*:*"}
            ]}]}],
        }},
    ]
}

_CPE = "cpe:2.3:a:apache:http_server"
_KW = ["apache", "httpd"]


def test_parse_extracts_exact_version():
    entries = parse_response(_SAMPLE, _CPE, _KW)
    e = next(x for x in entries if x["id"] == "CVE-2021-41773")
    # exact CPE version -> introduced == last_affected == 2.4.49
    assert e["ranges"] == [{"introduced": "2.4.49", "last_affected": "2.4.49"}]
    assert e["severity"] == "high" and e["cvss"] == 7.5
    assert e["keywords"] == ["apache", "httpd"]


def test_parse_extracts_version_range():
    entries = parse_response(_SAMPLE, _CPE, _KW)
    e = next(x for x in entries if x["id"] == "CVE-2021-44224")
    assert e["ranges"] == [{"introduced": "2.4.7", "last_affected": "2.4.51"}]


def test_parse_ignores_other_products():
    entries = parse_response(_SAMPLE, _CPE, _KW)
    ids = {e["id"] for e in entries}
    assert "CVE-9999-0000" not in ids       # different CPE prefix
    assert ids == {"CVE-2021-41773", "CVE-2021-44224"}


def test_parsed_entries_match_via_engine():
    # the synced entries must be usable by the real matcher
    from ..config import Config
    from ..cve.engine import CVEEngine
    from ..models import Host, Port, PortState, Service

    entries = parse_response(_SAMPLE, _CPE, _KW)
    eng = CVEEngine(Config())
    eng.db = entries                      # use only the synced entries
    h = Host(ip="192.0.2.10")
    h.ports[80] = Port(80, state=PortState.OPEN,
                       service=Service(name="http", product="Apache httpd",
                                       version="2.4.49"))
    titles = {f.title.split(":")[0] for f in eng.assess_port(h, h.ports[80])}
    assert "CVE-2021-41773" in titles
    assert "CVE-2021-44224" in titles     # 2.4.49 is within 2.4.7..2.4.51


def test_merge_unions_keywords_and_ranges():
    a = [{"id": "CVE-1", "keywords": ["nginx"], "ranges": [{"fixed": "1.0"}]}]
    b = [{"id": "CVE-1", "keywords": ["nginx", "x"], "ranges": [{"fixed": "2.0"}]},
         {"id": "CVE-2", "keywords": ["apache"], "ranges": []}]
    merged = merge_entries(a, b)
    m1 = next(e for e in merged if e["id"] == "CVE-1")
    assert set(m1["keywords"]) == {"nginx", "x"}
    assert {"fixed": "1.0"} in m1["ranges"] and {"fixed": "2.0"} in m1["ranges"]
    assert len(merged) == 2


def _run_all():
    fns = [v for k, v in globals().items() if k.startswith("test_")]
    for fn in fns:
        fn()
        print(f"  ok  {fn.__name__}")
    print(f"\n{len(fns)}/{len(fns)} tests passed")


if __name__ == "__main__":
    _run_all()

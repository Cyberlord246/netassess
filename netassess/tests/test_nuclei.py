"""Tests for the nuclei adapter (argv profile + JSONL parsing). No network.

Run: python -m netassess.tests.test_nuclei
"""
from __future__ import annotations

from ..adapters.nuclei_adapter import NucleiAdapter
from ..models import Severity, ValidationState


def test_light_profile_flags():
    a = NucleiAdapter()
    argv = a.build_argv("urls.txt")
    # light-keeping flags present
    for flag in ("-jsonl", "-silent", "-duc", "-no-interactsh", "-rl", "-c",
                 "-bs", "-exclude-tags", "-tags"):
        assert flag in argv, flag
    # heavy classes excluded
    ex = argv[argv.index("-exclude-tags") + 1]
    for t in ("dos", "fuzzing", "intrusive", "brute-force", "headless"):
        assert t in ex
    # light profile restricts to lightweight tags
    tags = argv[argv.index("-tags") + 1]
    assert "exposures" in tags and "cve" in tags


def test_thorough_drops_tag_restriction():
    a = NucleiAdapter()
    argv = a.build_argv("urls.txt", thorough=True)
    assert "-tags" not in argv          # no include-restriction => broader run
    assert "-exclude-tags" in argv      # still excludes the heavy classes


def test_rate_is_wired():
    a = NucleiAdapter()
    argv = a.build_argv("urls.txt", rate=15)
    assert argv[argv.index("-rl") + 1] == "15"


def test_parse_jsonl_skips_noise():
    a = NucleiAdapter()
    out = a.parse_jsonl('garbage\n{"template-id":"x","info":{"name":"n","severity":"low"},"matched-at":"http://h/"}\n')
    assert len(out) == 1 and out[0]["template-id"] == "x"


def test_finding_from_cve_template():
    a = NucleiAdapter()
    obj = {
        "template-id": "CVE-2021-41773",
        "info": {"name": "Apache 2.4.49 Path Traversal", "severity": "high",
                 "description": "path traversal",
                 "reference": ["https://nvd.nist.gov/vuln/detail/CVE-2021-41773"],
                 "classification": {"cve-id": ["CVE-2021-41773"], "cvss-score": 7.5},
                 "tags": ["cve", "lfi"]},
        "matched-at": "https://192.0.2.10:443/cgi-bin/",
        "ip": "192.0.2.10",
    }
    f = a._to_finding(obj)
    assert f.severity == Severity.HIGH
    assert f.asset == "192.0.2.10:443"
    assert "CVE-2021-41773" in f.title          # enables KEV/EPSS enrichment
    assert "CVE-2021-41773" in f.evidence
    assert f.validation == ValidationState.CONFIRMED
    assert f.source == "nuclei"


def test_finding_asset_from_url_without_ip():
    a = NucleiAdapter()
    obj = {"template-id": "exposed-panel", "info": {"name": "Panel", "severity": "info"},
           "matched-at": "http://app.example.com:8080/admin"}
    f = a._to_finding(obj)
    assert f.asset == "app.example.com:8080"


def test_kev_enrichment_applies_to_nuclei_cve():
    # a nuclei CVE finding should be enrichable by KEV/EPSS via its title
    from ..cve.kev import KEVData
    a = NucleiAdapter()
    obj = {"template-id": "CVE-2021-41773",
           "info": {"name": "Apache path traversal", "severity": "medium",
                    "classification": {"cve-id": ["CVE-2021-41773"]}},
           "matched-at": "https://192.0.2.10/", "ip": "192.0.2.10"}
    f = a._to_finding(obj)
    data = KEVData(kev={"CVE-2021-41773": {"ransomware": False}},
                   epss={"CVE-2021-41773": 0.9})
    data.enrich_finding(f)
    assert f.kev is True and f.epss == 0.9


def _run_all():
    fns = [v for k, v in globals().items() if k.startswith("test_")]
    for fn in fns:
        fn()
        print(f"  ok  {fn.__name__}")
    print(f"\n{len(fns)}/{len(fns)} tests passed")


if __name__ == "__main__":
    _run_all()

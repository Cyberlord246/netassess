"""Tests for version comparison and CVE matching.

Run: python -m netassess.tests.test_cve
"""
from __future__ import annotations

from ..config import Config
from ..cve.engine import CVEEngine
from ..cve.version import compare, in_range, parse_version
from ..models import Host, Port, Service, PortState, HTTPService, Technology


def test_parse_basic():
    assert parse_version("2.4.49") == (2, 4, 49)
    assert parse_version("7.7") == (7, 7)


def test_parse_openssh_portable():
    # 9.3 < 9.3p2
    assert compare("9.3", "9.3p2") == -1
    assert compare("9.3p2", "9.3p2") == 0
    assert compare("8.9p1", "9.3p2") == -1


def test_parse_openssl_letter():
    # 1.0.1f < 1.0.1g
    assert compare("1.0.1f", "1.0.1g") == -1


def test_in_range_fixed_exclusive():
    assert in_range("2.4.49", "2.4.49", "2.4.50") is True
    assert in_range("2.4.50", "2.4.49", "2.4.50") is False   # fixed is exclusive
    assert in_range("2.4.48", "2.4.49", "2.4.50") is False


def test_in_range_open_lower():
    assert in_range("7.6", None, "7.7") is True
    assert in_range("7.7", None, "7.7") is False


def test_in_range_last_affected_inclusive():
    assert in_range("2.3.4", "2.3.4", None, "2.3.4") is True
    assert in_range("2.3.5", "2.3.4", None, "2.3.4") is False


def _host_with(product="", version="", banner="", name="ssh", port=22):
    h = Host(ip="192.0.2.10")
    svc = Service(name=name, product=product, version=version, banner=banner)
    h.ports[port] = Port(number=port, state=PortState.OPEN, service=svc)
    return h


def test_cve_match_apache_4149():
    cfg = Config()
    eng = CVEEngine(cfg)
    h = _host_with(product="Apache httpd", version="2.4.49", name="http", port=80)
    findings = eng.assess_port(h, h.ports[80])
    ids = {f.title.split(":")[0] for f in findings}
    assert "CVE-2021-41773" in ids
    assert "CVE-2021-42013" in ids


def test_cve_no_match_patched_apache():
    cfg = Config()
    eng = CVEEngine(cfg)
    h = _host_with(product="Apache httpd", version="2.4.62", name="http", port=80)
    findings = eng.assess_port(h, h.ports[80])
    assert findings == []


def test_cve_openssh_regresshion():
    cfg = Config()
    eng = CVEEngine(cfg)
    h = _host_with(product="OpenSSH", version="8.9p1", name="ssh", port=22)
    findings = eng.assess_port(h, h.ports[22])
    ids = {f.title.split(":")[0] for f in findings}
    assert "CVE-2024-6387" in ids


def test_cve_from_http_server_header():
    cfg = Config()
    eng = CVEEngine(cfg)
    h = Host(ip="192.0.2.10")
    h.ports[443] = Port(number=443, state=PortState.OPEN,
                        service=Service(name="https"))
    h.http_services.append(HTTPService(
        url="https://192.0.2.10/", ip="192.0.2.10", port=443, scheme="https",
        server="nginx/1.17.6"))
    findings = eng.assess_port(h, h.ports[443])
    ids = {f.title.split(":")[0] for f in findings}
    assert "CVE-2019-20372" in ids  # nginx < 1.17.7


def test_cve_findings_are_needs_validation():
    cfg = Config()
    eng = CVEEngine(cfg)
    h = _host_with(product="OpenSSH", version="7.2", name="ssh", port=22)
    findings = eng.assess_port(h, h.ports[22])
    assert findings
    from ..models import ValidationState
    assert all(f.validation == ValidationState.NEEDS_VALIDATION for f in findings)


def _run_all():
    fns = [v for k, v in globals().items() if k.startswith("test_")]
    for fn in fns:
        fn()
        print(f"  ok  {fn.__name__}")
    print(f"\n{len(fns)}/{len(fns)} tests passed")


if __name__ == "__main__":
    _run_all()

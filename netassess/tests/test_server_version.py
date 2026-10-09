"""Server header -> service product/version mapping (so web servers show a
version in the report even without nmap -sV).

Run: python -m netassess.tests.test_server_version
"""
from __future__ import annotations

from ..models import Confidence, Port, PortState, Service
from ..services import apply_server_version


def _port():
    return Port(number=443, state=PortState.OPEN, service=Service(name="https"))


def test_product_and_version_parsed():
    p = _port()
    apply_server_version(p, "nginx/1.18.0")
    assert p.service.product == "nginx" and p.service.version == "1.18.0"


def test_apache_with_os_comment():
    p = _port()
    apply_server_version(p, "Apache/2.4.49 (Ubuntu)")
    assert p.service.product == "Apache" and p.service.version == "2.4.49"


def test_iis_version():
    p = _port()
    apply_server_version(p, "Microsoft-IIS/10.0")
    assert p.service.product == "Microsoft-IIS" and p.service.version == "10.0"


def test_no_version_still_sets_product():
    p = _port()
    apply_server_version(p, "cloudflare")
    assert p.service.product == "cloudflare" and p.service.version == ""


def test_does_not_override_existing_sv_result():
    p = Port(number=443, state=PortState.OPEN,
             service=Service(name="https", product="nginx", version="1.25.3"))
    apply_server_version(p, "nginx/1.18.0")      # e.g. a stale/again header
    assert p.service.version == "1.25.3"         # existing -sV value preserved


def test_empty_server_noop():
    p = _port()
    apply_server_version(p, "")
    assert p.service.product == "" and p.service.version == ""


def _run_all():
    fns = [v for k, v in globals().items() if k.startswith("test_")]
    for fn in fns:
        fn()
        print(f"  ok  {fn.__name__}")
    print(f"\n{len(fns)}/{len(fns)} tests passed")


if __name__ == "__main__":
    _run_all()

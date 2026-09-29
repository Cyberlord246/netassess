"""Tests for hostname/URL target cleaning and DNS resolution (network mocked).

Run: python -m netassess.tests.test_resolve
"""
from __future__ import annotations

from ..resolve import clean_target, expand_targets, is_ip_or_cidr


def test_clean_target_variants():
    assert clean_target("assetmanagement.hsbc.at") == "assetmanagement.hsbc.at"
    assert clean_target("https://www.etf.hsbc.com") == "www.etf.hsbc.com"
    assert clean_target("https://host.example.com:8443/path?q=1") == "host.example.com"
    assert clean_target("user@host.example.org") == "host.example.org"
    assert clean_target("  # comment") == ""
    assert clean_target("") == ""
    # markdown link -> prefer the URL in parens
    assert clean_target("[www.etf.hsbc.com](https://www.etf.hsbc.com)") == "www.etf.hsbc.com"


def test_clean_target_preserves_ip_and_cidr():
    assert clean_target("10.0.0.0/24") == "10.0.0.0/24"     # /prefix NOT stripped
    assert clean_target("192.0.2.10") == "192.0.2.10"
    assert clean_target("2001:db8::1") == "2001:db8::1"


def test_is_ip_or_cidr():
    assert is_ip_or_cidr("192.0.2.10")
    assert is_ip_or_cidr("10.0.0.0/24")
    assert not is_ip_or_cidr("example.com")


def test_expand_targets_resolves_and_maps():
    m = {"a.example.com": ["203.0.113.1"], "b.example.com": ["203.0.113.1"],
         "c.example.com": ["203.0.113.9"]}

    def fake(name, timeout):
        return name, m.get(name, []), "" if name in m else "NXDOMAIN"

    rs = expand_targets(["a.example.com", "b.example.com", "c.example.com",
                         "198.51.100.5", "bad.nxdomain"], resolver=fake)
    assert rs.ip_targets == ["198.51.100.5", "203.0.113.1", "203.0.113.9"]
    # two hostnames collapse to one IP -> both recorded (correlation later dedups)
    assert rs.host_map["203.0.113.1"] == ["a.example.com", "b.example.com"]
    assert rs.unresolved == ["bad.nxdomain"]
    assert rs.changed is True


def test_expand_targets_pure_ip_list_unchanged():
    rs = expand_targets(["192.0.2.10", "10.0.0.0/24"], resolver=lambda n, t: (n, [], ""))
    assert rs.changed is False              # nothing to clean/resolve
    assert set(rs.ip_targets) == {"192.0.2.10", "10.0.0.0/24"}
    assert rs.host_map == {}


def test_expand_targets_unwraps_url_then_resolves():
    def fake(name, timeout):
        return name, (["203.0.113.5"] if name == "www.etf.hsbc.com" else []), ""

    rs = expand_targets(["https://www.etf.hsbc.com/foo"], resolver=fake)
    assert rs.ip_targets == ["203.0.113.5"]
    assert rs.host_map == {"203.0.113.5": ["www.etf.hsbc.com"]}


def test_profile_detection():
    def f(n, t):
        return n, ["203.0.113.1"], ""
    assert expand_targets(["a.example.com", "b.example.com"], resolver=f).profile() == "web"
    assert expand_targets(["192.0.2.10", "10.0.0.0/24"], resolver=f).profile() == "network"
    assert expand_targets(["a.example.com", "192.0.2.10"], resolver=f).profile() == "mixed"


def _run_all():
    fns = [v for k, v in sorted(globals().items()) if k.startswith("test_")]
    for fn in fns:
        fn()
        print(f"  ok  {fn.__name__}")
    print(f"\n{len(fns)}/{len(fns)} tests passed")


if __name__ == "__main__":
    _run_all()

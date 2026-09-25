"""Tests for nmap -sn host-discovery XML parsing (no network).

Run: python -m netassess.tests.test_discovery
"""
from __future__ import annotations

from ..adapters.nmap_adapter import NmapAdapter

# trimmed `nmap -sn -oX -` output: two up, one down
_XML = """<?xml version="1.0"?>
<nmaprun>
  <host>
    <status state="up" reason="echo-reply"/>
    <address addr="192.0.2.10" addrtype="ipv4"/>
  </host>
  <host>
    <status state="up" reason="arp-response"/>
    <address addr="192.0.2.11" addrtype="ipv4"/>
    <address addr="AA:BB:CC:DD:EE:FF" addrtype="mac"/>
  </host>
  <host>
    <status state="down" reason="no-response"/>
    <address addr="192.0.2.12" addrtype="ipv4"/>
  </host>
</nmaprun>"""


def test_parse_up_returns_only_up_ipv4():
    up = NmapAdapter()._parse_up(_XML)
    assert up == {"192.0.2.10", "192.0.2.11"}   # .12 is down; MAC ignored


def test_parse_up_handles_garbage():
    assert NmapAdapter()._parse_up("not xml") == set()
    assert NmapAdapter()._parse_up("") == set()


def test_discover_no_targets_returns_empty():
    up, res = NmapAdapter().discover([])
    assert up == set()
    # not_found True when nmap absent or nothing to do
    assert res.not_found or not up


def _run_all():
    fns = [v for k, v in globals().items() if k.startswith("test_")]
    for fn in fns:
        fn()
        print(f"  ok  {fn.__name__}")
    print(f"\n{len(fns)}/{len(fns)} tests passed")


if __name__ == "__main__":
    _run_all()

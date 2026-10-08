"""Tests for nmap import (XML + greppable) and --skip-portscan.

Run: python -m netassess.tests.test_nmap_import
"""
from __future__ import annotations

import os
import tempfile

from ..cli import build_parser, _build_config
from ..nmap_import import parse

_XML = """<?xml version="1.0"?>
<nmaprun>
  <host>
    <address addr="192.0.2.10" addrtype="ipv4"/>
    <address addr="AA:BB:CC:DD:EE:FF" addrtype="mac"/>
    <ports>
      <port protocol="tcp" portid="22"><state state="open"/>
        <service name="ssh" product="OpenSSH" version="8.9"/></port>
      <port protocol="tcp" portid="80"><state state="open"/>
        <service name="http" product="nginx" version="1.18.0"/></port>
      <port protocol="tcp" portid="81"><state state="closed"/></port>
      <port protocol="udp" portid="53"><state state="open"/></port>
    </ports>
  </host>
</nmaprun>
"""

_GNMAP = ("Host: 192.0.2.20 ()\tPorts: 443/open/tcp//https//nginx/1.20/, "
          "3306/open/tcp//mysql///, 8080/closed/tcp//http///\n")


def _write(content, suffix):
    fd, path = tempfile.mkstemp(suffix=suffix)
    with os.fdopen(fd, "w", encoding="utf-8") as fh:
        fh.write(content)
    return path


def test_parse_xml_open_tcp_only_with_versions():
    path = _write(_XML, ".xml")
    try:
        res = parse(path)
    finally:
        os.unlink(path)
    assert set(res) == {"192.0.2.10"}
    ports = {p["port"]: p for p in res["192.0.2.10"]}
    assert set(ports) == {22, 80}                 # closed + udp excluded
    assert ports[80]["product"] == "nginx" and ports[80]["version"] == "1.18.0"


def test_parse_greppable():
    path = _write(_GNMAP, ".gnmap")
    try:
        res = parse(path)
    finally:
        os.unlink(path)
    ports = {p["port"] for p in res["192.0.2.20"]}
    assert ports == {443, 3306}                   # closed excluded
    svc = {p["port"]: p["service"] for p in res["192.0.2.20"]}
    assert svc[443] == "https"


def test_skip_portscan_sets_flag_and_web_ports():
    a = build_parser().parse_args(["scan", "--targets", "192.0.2.10",
                                   "--skip-portscan"])
    cfg = _build_config(a)
    assert cfg.skip_portscan is True
    # no explicit --ports -> limited to the common web set (not top-1000)
    assert len(cfg.effective_ports()) < 20


def test_skip_portscan_respects_explicit_ports():
    a = build_parser().parse_args(["scan", "--targets", "192.0.2.10",
                                   "--skip-portscan", "--ports", "22,2222"])
    cfg = _build_config(a)
    assert cfg.skip_portscan is True
    assert set(cfg.effective_ports()) == {22, 2222}


def _run_all():
    fns = [v for k, v in globals().items() if k.startswith("test_")]
    for fn in fns:
        fn()
        print(f"  ok  {fn.__name__}")
    print(f"\n{len(fns)}/{len(fns)} tests passed")


if __name__ == "__main__":
    _run_all()

"""Service product/version capture and reporting.

Guards the fixes for "the report does not show which version of services":
  * probes fill product/version WITHOUT clobbering nmap -sV results;
  * SSH/DNS/SMTP/MariaDB identifiers are split into product + version;
  * banner parsing never takes an IP/hostname as the version;
  * the Markdown + HTML reports list every open port with its version.

Run: python -m netassess.tests.test_service_versions
"""
from __future__ import annotations

import socket

from ..config import Config
from ..models import Confidence, Host, Port, PortState, Service
from ..probers import SMBProbe, SSHProbe
from ..probers import service_probes as sp
from ..scope import ScopeEngine
from ..services import set_service_version, split_software
from .test_smb import _FakeSock, _smb2_response


# -- helpers --------------------------------------------------------------- #
def test_split_software():
    assert split_software("OpenSSH_8.9p1 Ubuntu-3ubuntu0.6") == ("OpenSSH", "8.9p1")
    assert split_software("OpenSSH_for_Windows_8.1") == ("OpenSSH_for_Windows", "8.1")
    assert split_software("dropbear_2022.83") == ("dropbear", "2022.83")
    assert split_software("dnsmasq-2.86") == ("dnsmasq", "2.86")
    assert split_software("unbound 1.13.1") == ("unbound", "1.13.1")
    assert split_software("PowerDNS Recursor 4.8.1") == ("PowerDNS Recursor", "4.8.1")
    assert split_software("9.18.18-0ubuntu0.22.04.1-Ubuntu") == ("", "9.18.18")
    assert split_software("nginx") == ("nginx", "")
    assert split_software("") == ("", "")


def test_set_service_version_never_clobbers_or_downgrades():
    p = Port(22, state=PortState.OPEN,
             service=Service(name="ssh", product="OpenSSH", version="8.9p1",
                             confidence=Confidence.HIGH))
    set_service_version(p, "OpenSSH_8.9p1 Ubuntu", "", confidence=Confidence.MEDIUM)
    assert p.service.product == "OpenSSH" and p.service.version == "8.9p1"
    assert p.service.confidence == Confidence.HIGH          # not downgraded
    q = Port(21, state=PortState.OPEN, service=Service(name="ftp"))
    set_service_version(q, "vsftpd", "3.0.3", confidence=Confidence.HIGH)
    assert (q.service.product, q.service.version) == ("vsftpd", "3.0.3")
    assert q.service.confidence == Confidence.HIGH          # upgraded


def test_banner_version_ignores_leading_ip_and_hostname():
    p, v = sp.banner_product_version("220 10.0.0.5 ESMTP Exim 4.94.2 Tue, 12 Nov")
    assert (p, v) == ("exim", "4.94.2")
    p, v = sp.banner_product_version("220 mx1.example.com ESMTP Postfix (Ubuntu)")
    assert (p, v) == ("postfix", "")                         # no version disclosed
    p, v = sp.banner_product_version("220 192.168.1.4 FTP server ready")
    assert (p, v) == ("", "")                                # IP is not a version
    p, v = sp.banner_product_version(
        "220 mail Microsoft ESMTP MAIL Service, Version: 10.0.17763.1 ready")
    assert (p, v) == ("microsoft esmtp", "10.0.17763.1")
    p, v = sp.banner_product_version("220 h ESMTP Sendmail 8.15.2/8.15.2; Tue")
    assert (p, v) == ("sendmail", "8.15.2")


# -- probes --------------------------------------------------------------- #
def _ssh(port, banner):
    cfg = Config(targets=["10.0.0.9"])
    pr = SSHProbe(cfg, ScopeEngine(cfg))
    orig = sp._recv_banner
    sp._recv_banner = lambda *a, **k: (banner, "")
    try:
        pr.probe(Host(ip="10.0.0.9"), port)
    finally:
        sp._recv_banner = orig
    return port


def test_ssh_probe_splits_product_and_version():
    p = _ssh(Port(22, state=PortState.OPEN, service=Service(name="ssh")),
             b"SSH-2.0-OpenSSH_8.9p1 Ubuntu-3ubuntu0.6\r\n")
    assert p.service.product == "OpenSSH" and p.service.version == "8.9p1"
    assert "OpenSSH_8.9p1" in p.service.evidence


def test_ssh_probe_keeps_nmap_result():
    p = _ssh(Port(22, state=PortState.OPEN,
                  service=Service(name="ssh", product="OpenSSH",
                                  version="8.9p1 Ubuntu 3ubuntu0.6",
                                  confidence=Confidence.HIGH)),
             b"SSH-2.0-OpenSSH_8.9p1 Ubuntu-3ubuntu0.6\r\n")
    assert p.service.product == "OpenSSH"
    assert p.service.version == "8.9p1 Ubuntu 3ubuntu0.6"   # nmap's value kept


def _smb(service):
    cfg = Config(targets=["10.0.0.9"])
    pr = SMBProbe(cfg, ScopeEngine(cfg))
    p = Port(445, state=PortState.OPEN, service=service)
    shared = [_smb2_response(0x0311), b"\x00\x00\x00\x00rubbish"]
    orig = socket.socket
    socket.socket = lambda *a, **k: _FakeSock(shared)
    try:
        pr.probe(Host(ip="10.0.0.9"), p)
    finally:
        socket.socket = orig
    return p


def test_smb_keeps_nmap_samba_version_and_records_dialect():
    p = _smb(Service(name="netbios-ssn", product="Samba smbd", version="4.15.13",
                     confidence=Confidence.HIGH))
    assert p.service.product == "Samba smbd" and p.service.version == "4.15.13"
    assert "3.1.1" in p.service.evidence                    # dialect as evidence


def test_smb_without_nmap_uses_dialect_as_version():
    p = _smb(Service(name="microsoft-ds"))
    assert p.service.product == "SMB" and p.service.version == "3.1.1"


def test_dns_version_bind_bare_number_is_bind():
    cfg = Config(targets=["10.0.0.9"])
    pr = sp.DNSProbe(cfg, ScopeEngine(cfg))
    pr._extract_txt = lambda *_a, **_k: "9.18.18-0ubuntu0.22.04.1-Ubuntu"
    pr._recursion_open = lambda *a, **k: False
    pr._candidate_zones = lambda *a, **k: []
    orig = sp._recv_banner
    sp._recv_banner = lambda *a, **k: (b"\x00\x10" + b"\x00" * 16, "")
    p = Port(53, state=PortState.OPEN, service=Service(name="dns"))
    try:
        pr.probe(Host(ip="10.0.0.9"), p)
    finally:
        sp._recv_banner = orig
    assert p.service.product == "ISC BIND" and p.service.version == "9.18.18"


# -- reports -------------------------------------------------------------- #
def _graph():
    from ..state import AssetGraph
    g = AssetGraph()
    h = g.get_or_create("10.0.0.9")
    h.ports[22] = Port(22, state=PortState.OPEN,
                       service=Service(name="ssh", product="OpenSSH",
                                       version="8.9p1"))
    h.ports[8081] = Port(8081, state=PortState.OPEN,
                         service=Service(name="unknown"))
    return g


def test_markdown_versions_table_lists_every_port():
    from ..report import ReportGenerator
    rg = ReportGenerator.__new__(ReportGenerator)
    rg.graph = _graph()
    md = rg._service_versions()
    assert "| 10.0.0.9:22/tcp | ssh | OpenSSH | 8.9p1 |" in md
    assert "10.0.0.9:8081/tcp" in md                         # unversioned shown
    assert "show no version" in md


def test_html_has_services_and_versions_table():
    from ..report_html import HTMLReport
    rg = HTMLReport.__new__(HTMLReport)
    rg.graph = _graph()
    out = rg._services()
    assert "Services &amp; Versions" in out
    assert "OpenSSH" in out and "8.9p1" in out
    assert "22/ssh (OpenSSH 8.9p1)" in rg._hosts()


def _run_all():
    fns = [v for k, v in globals().items() if k.startswith("test_")]
    for fn in fns:
        fn()
        print(f"  ok  {fn.__name__}")
    print(f"\n{len(fns)}/{len(fns)} tests passed")


if __name__ == "__main__":
    _run_all()

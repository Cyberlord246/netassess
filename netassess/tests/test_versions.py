"""Tests for banner/handshake version extraction (feeds the CVE engine).

Run: python -m netassess.tests.test_versions
"""
from __future__ import annotations

from ..probers.service_probes import banner_product_version, parse_mysql_greeting


def test_ftp_vsftpd():
    p, v = banner_product_version("220 (vsFTPd 3.0.3)")
    assert p == "vsftpd" and v == "3.0.3"


def test_ftp_proftpd():
    p, v = banner_product_version("220 ProFTPD 1.3.5 Server ready.")
    assert p == "proftpd" and v == "1.3.5"


def test_imap_dovecot():
    p, v = banner_product_version("* OK [CAPABILITY IMAP4rev1] Dovecot ready.")
    assert p == "dovecot"


def test_no_product():
    p, v = banner_product_version("220 mail service ready")
    assert p == "" and v == ""


def test_mysql_greeting_version():
    # length(3) + seq(1) + protocol(0x0a) + "8.0.32\0" + ...
    body = b"\x0a" + b"8.0.32\x00" + b"\x00" * 20
    pkt = b"\x2a\x00\x00\x00" + body
    prod, ver = parse_mysql_greeting(pkt)
    assert prod == "mysql" and ver == "8.0.32"


def test_mariadb_greeting_version():
    body = b"\x0a" + b"5.5.5-10.5.15-MariaDB\x00" + b"\x00" * 10
    pkt = b"\x00\x00\x00\x00" + body
    prod, ver = parse_mysql_greeting(pkt)
    assert prod == "mariadb" and "MariaDB" in ver


def test_mysql_greeting_invalid():
    assert parse_mysql_greeting(b"\x00\x00\x00\x00\xff") == ("", "")


def test_extracted_version_drives_cve_match():
    # a proftpd version extracted from a banner should match a CVE entry
    from ..config import Config
    from ..cve.engine import CVEEngine
    from ..models import Host, Port, PortState, Service
    eng = CVEEngine(Config())
    # inject a matching CVE entry for proftpd
    eng.db = [{"id": "CVE-2015-3306", "product": "proftpd",
               "keywords": ["proftpd"], "ranges": [{"introduced": "1.3.5",
               "last_affected": "1.3.5"}], "cvss": 10.0, "severity": "critical",
               "summary": "ProFTPD 1.3.5 mod_copy RCE", "references": []}]
    h = Host(ip="192.0.2.10")
    prod, ver = banner_product_version("220 ProFTPD 1.3.5 Server ready.")
    h.ports[21] = Port(21, state=PortState.OPEN,
                       service=Service(name="ftp", product=prod, version=ver))
    titles = {f.title.split(":")[0] for f in eng.assess_port(h, h.ports[21])}
    assert "CVE-2015-3306" in titles


def _run_all():
    fns = [v for k, v in globals().items() if k.startswith("test_")]
    for fn in fns:
        fn()
        print(f"  ok  {fn.__name__}")
    print(f"\n{len(fns)}/{len(fns)} tests passed")


if __name__ == "__main__":
    _run_all()

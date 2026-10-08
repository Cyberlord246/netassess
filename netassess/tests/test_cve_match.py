"""Tests for CPE-style (word-boundary) CVE matching precision.

Run: python -m netassess.tests.test_cve_match
"""
from __future__ import annotations

from ..config import Config
from ..cve.engine import CVEEngine


def _eng():
    return CVEEngine(Config(targets=["192.0.2.10"]))


def test_word_boundary_blocks_substring_fp():
    e = _eng()
    ssl_entry = {"id": "X", "keywords": ["ssl"],
                 "ranges": [{"introduced": "0", "fixed": "99"}]}
    # 'ssl' must NOT match inside another word ('wassl' or 'openssl')
    assert e._match_entry("wassl", "1.0", ssl_entry) is False
    assert e._match_entry("openssl 1.0.1f", "1.0.1f", ssl_entry) is False
    # the correct product keyword matches, incl. a glued version
    openssl_entry = {"id": "Y", "keywords": ["openssl"],
                     "ranges": [{"introduced": "0", "fixed": "99"}]}
    assert e._match_entry("openssl 1.0.1f", "1.0.1f", openssl_entry) is True
    assert e._match_entry("OpenSSL/1.0.1f", "1.0.1f", openssl_entry) is True


def test_ftp_not_matched_in_sftp():
    e = _eng()
    entry = {"id": "X", "keywords": ["ftp"],
             "ranges": [{"introduced": "0", "fixed": "99"}]}
    assert e._match_entry("sftp server", "1.0", entry) is False
    assert e._match_entry("ftp server", "1.0", entry) is True


def test_exclude_keyword_vetoes_match():
    e = _eng()
    entry = {"id": "X", "keywords": ["apache"], "exclude_keywords": ["tomcat"],
             "ranges": [{"introduced": "0", "fixed": "99"}]}
    assert e._match_entry("Apache Tomcat", "9.0", entry) is False
    assert e._match_entry("Apache httpd", "2.4", entry) is True


def test_cpe_derives_vendor_product_keywords():
    e = _eng()
    entry = {"id": "X", "cpe": "cpe:2.3:a:nginx:nginx:1.18.0:*:*:*:*:*:*:*",
             "ranges": [{"introduced": "0", "fixed": "99"}]}
    assert e._match_entry("nginx/1.18.0", "1.18.0", entry) is True


def test_apache_cve_does_not_match_tomcat_in_kb():
    e = _eng()
    # real KB apache httpd CVEs must not fire on Tomcat
    fired = [ent["id"] for ent in e.db
             if e._match_entry("Apache Tomcat", "2.4.49", ent)
             and "httpd" in " ".join(ent.get("keywords", []))]
    assert fired == []


def _run_all():
    fns = [v for k, v in globals().items() if k.startswith("test_")]
    for fn in fns:
        fn()
        print(f"  ok  {fn.__name__}")
    print(f"\n{len(fns)}/{len(fns)} tests passed")


if __name__ == "__main__":
    _run_all()

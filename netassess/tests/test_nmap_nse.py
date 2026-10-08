"""Tests for the nmap NSE vuln adapter's XML parsing + finding mapping.

Run: python -m netassess.tests.test_nmap_nse
"""
from __future__ import annotations

from ..adapters.nmap_nse import NmapNSEAdapter
from ..models import Severity, ValidationState

# vulners-style: structured elems + a text table
_XML = """<?xml version="1.0"?>
<nmaprun>
  <host>
    <address addr="192.0.2.10" addrtype="ipv4"/>
    <ports>
      <port protocol="tcp" portid="22">
        <state state="open"/>
        <script id="vulners" output="cpe:/a:openbsd:openssh:7.4&#10;  CVE-2018-15473  5.3  https://vulners.com/cve/CVE-2018-15473">
          <table key="cpe:/a:openbsd:openssh:7.4">
            <table>
              <elem key="id">CVE-2018-15473</elem>
              <elem key="cvss">5.3</elem>
            </table>
            <table>
              <elem key="id">CVE-2016-10009</elem>
              <elem key="cvss">7.5</elem>
            </table>
          </table>
        </script>
      </port>
    </ports>
  </host>
</nmaprun>
"""


def test_parse_extracts_cves_and_cvss():
    rows = NmapNSEAdapter().parse_xml(_XML)
    by_cve = {r["cve"]: r for r in rows}
    assert "CVE-2018-15473" in by_cve and "CVE-2016-10009" in by_cve
    assert by_cve["CVE-2016-10009"]["cvss"] == 7.5
    assert all(r["ip"] == "192.0.2.10" and r["port"] == "22" for r in rows)


def test_to_findings_severity_from_cvss():
    rows = NmapNSEAdapter().parse_xml(_XML)
    fs = {f.title.split(":")[0]: f for f in NmapNSEAdapter().to_findings(rows)}
    assert fs["CVE-2016-10009"].severity == Severity.HIGH      # 7.5
    assert fs["CVE-2018-15473"].severity == Severity.MEDIUM    # 5.3
    f = fs["CVE-2016-10009"]
    assert f.asset == "192.0.2.10:22"
    assert f.category == "known-vulnerability"
    assert f.validation == ValidationState.NEEDS_VALIDATION
    assert f.source == "nmap-nse"


def test_build_argv():
    argv = NmapNSEAdapter().build_argv("/tmp/t.txt", "22,80", script="vuln")
    assert "--script" in argv and argv[argv.index("--script") + 1] == "vuln"
    assert "-p" in argv and "22,80" in argv


def _run_all():
    fns = [v for k, v in globals().items() if k.startswith("test_")]
    for fn in fns:
        fn()
        print(f"  ok  {fn.__name__}")
    print(f"\n{len(fns)}/{len(fns)} tests passed")


if __name__ == "__main__":
    _run_all()

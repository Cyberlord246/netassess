"""SMB null-session / share enumeration adapter (parsers + findings).

Run: python -m netassess.tests.test_smb_enum
"""
from __future__ import annotations

from ..adapters.smb_enum import SmbEnumAdapter
from ..models import Severity, ValidationState

_SMBCLIENT_OK = """\
Disk|ADMIN$|Remote Admin
Disk|C$|Default share
IPC|IPC$|Remote IPC
Disk|backups|nightly db dumps
"""

_SMBCLIENT_DENIED = "session setup failed: NT_STATUS_ACCESS_DENIED"


def test_parse_smbclient_null_session_with_custom_share():
    r = SmbEnumAdapter().parse_smbclient(_SMBCLIENT_OK)
    assert r["null_session"] is True and r["denied"] is False
    names = {s["name"] for s in r["shares"]}
    assert names == {"ADMIN$", "C$", "IPC$", "backups"}


def test_parse_smbclient_denied():
    r = SmbEnumAdapter().parse_smbclient(_SMBCLIENT_DENIED)
    assert r["null_session"] is False and r["denied"] is True
    assert r["shares"] == []


def test_findings_custom_share_is_high():
    a = SmbEnumAdapter()
    r = a.parse_smbclient(_SMBCLIENT_OK)
    fs = a.to_findings("10.0.0.9", 445, r)
    assert len(fs) == 1
    f = fs[0]
    assert f.severity == Severity.HIGH            # non-default 'backups' share
    assert "backups" in f.evidence
    assert f.validation == ValidationState.CONFIRMED


def test_findings_only_admin_shares_is_medium():
    a = SmbEnumAdapter()
    r = a.parse_smbclient("Disk|ADMIN$|\nIPC|IPC$|\nDisk|C$|")
    f = a.to_findings("10.0.0.9", 445, r)[0]
    assert f.severity == Severity.MEDIUM          # only default admin shares


def test_findings_denied_is_low_informational():
    a = SmbEnumAdapter()
    r = a.parse_smbclient(_SMBCLIENT_DENIED)
    f = a.to_findings("10.0.0.9", 445, r)[0]
    assert f.severity == Severity.LOW and "denied" in f.title.lower()


def test_parse_nmap_shares():
    xml = ('<nmaprun><host><ports><port portid="445"><script '
           'id="smb-enum-shares" output="&#10;  \\\\10.0.0.9\\backups: &#10;'
           '    Anonymous access: READ&#10;  \\\\10.0.0.9\\IPC$: &#10;"/>'
           '</port></ports></host></nmaprun>')
    r = SmbEnumAdapter().parse_nmap(xml)
    names = {s["name"] for s in r["shares"]}
    assert "backups" in names
    assert r["null_session"] is True              # Anonymous access: READ


def _run_all():
    fns = [v for k, v in globals().items() if k.startswith("test_")]
    for fn in fns:
        fn()
        print(f"  ok  {fn.__name__}")
    print(f"\n{len(fns)}/{len(fns)} tests passed")


if __name__ == "__main__":
    _run_all()

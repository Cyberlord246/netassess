"""Tests for the feroxbuster adapter (argv construction + JSON parsing).

The binary need not be installed; these exercise the pure logic and the
normalisation into the Finding schema.

Run: python -m netassess.tests.test_ferox
"""
from __future__ import annotations

from ..adapters.feroxbuster_adapter import FeroxbusterAdapter, INTERESTING_STATUS


def test_argv_core_flags():
    a = FeroxbusterAdapter()
    argv = a.build_argv("https://t/", "wl.txt", threads=30, depth=3, timeout=6)
    assert argv[0] == "feroxbuster"
    # tuned-for-signal flags present
    assert "--auto-tune" in argv
    assert "--filter-status" in argv
    assert "--json" in argv
    assert "-k" in argv
    assert "--dont-scan" in argv
    # depth/threads wired through
    assert argv[argv.index("--depth") + 1] == "3"
    assert argv[argv.index("-t") + 1] == "30"


def test_argv_filters_noise_keeps_useful():
    a = FeroxbusterAdapter()
    argv = a.build_argv("https://t/", "wl.txt")
    fs = argv[argv.index("--filter-status") + 1]
    assert "404" in fs and "502" in fs        # noise filtered
    # useful non-200 codes are NOT filtered
    for keep in (200, 301, 401, 403):
        assert str(keep) not in fs.split(",")


def test_argv_extensions_and_thorough():
    a = FeroxbusterAdapter()
    argv = a.build_argv("https://t/", "wl.txt", extensions="php, bak ,sql",
                        thorough=True, rate=100)
    assert argv[argv.index("-x") + 1] == "php,bak,sql"   # spaces stripped
    assert "--collect-backups" in argv
    assert "--rate-limit" in argv


def test_parse_json_filters_and_extracts():
    a = FeroxbusterAdapter()
    stdout = "\n".join([
        '{"type":"response","url":"https://t/admin","status":301,"content_length":10}',
        '{"type":"response","url":"https://t/.env","status":200,"content_length":42}',
        '{"type":"response","url":"https://t/missing","status":404,"content_length":9}',
        '{"type":"statistics","status_200s":1}',
        'not json',
    ])
    recs = a.parse_json(stdout)
    urls = {r["url"] for r in recs}
    assert "https://t/admin" in urls          # 301 kept (useful)
    assert "https://t/.env" in urls           # 200 kept
    assert "https://t/missing" not in urls     # 404 filtered
    assert all(r["status"] in INTERESTING_STATUS for r in recs)


def test_scan_service_builds_graded_findings():
    from ..models import Host, HTTPService
    a = FeroxbusterAdapter()
    # monkeypatch run() to return canned JSON instead of executing the binary
    import netassess.adapters.feroxbuster_adapter as mod
    from ..adapters.process import ProcResult
    orig = mod.run
    mod.run = lambda *args, **kw: ProcResult(
        ok=True, returncode=0, stdout="\n".join([
            '{"type":"response","url":"https://192.0.2.10/.env","status":200,"content_length":42}',
            '{"type":"response","url":"https://192.0.2.10/admin","status":401,"content_length":12}',
        ]), stderr="")
    try:
        host = Host(ip="192.0.2.10")
        svc = HTTPService(url="https://192.0.2.10/", ip="192.0.2.10", port=443,
                          scheme="https")
        recs, findings, _res = a.scan_service(host, svc, wordlist="wl.txt")
    finally:
        mod.run = orig
    titles = {f.title for f in findings}
    assert any(".env" in t for t in titles)
    # .env graded high, source attributed to feroxbuster
    env = next(f for f in findings if ".env" in f.title)
    assert env.severity.value == "high"
    assert env.source == "feroxbuster"
    # 401 admin present but access-controlled (downgraded from medium to low)
    admin = next(f for f in findings if "admin" in f.title.lower())
    assert admin.severity.value in ("low", "medium")


def _run_all():
    fns = [v for k, v in globals().items() if k.startswith("test_")]
    for fn in fns:
        fn()
        print(f"  ok  {fn.__name__}")
    print(f"\n{len(fns)}/{len(fns)} tests passed")


if __name__ == "__main__":
    _run_all()

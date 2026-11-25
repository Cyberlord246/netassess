"""Content-discovery noise suppression: canonical/wildcard redirects, WAF 403s,
and the --content-filter-status hard drop.

Run: python -m netassess.tests.test_content_noise
"""
from __future__ import annotations

from ..content_discovery import (
    make_findings, parse_status_set, _is_canonical_redirect,
)
from ..adapters.feroxbuster_adapter import FeroxbusterAdapter


def _h(path, status, *, location="", category="common", sev=None, length=100):
    from ..models import Severity
    return {"path": path, "url": f"http://10.0.0.5/{path}", "status": status,
            "location": location, "category": category,
            "sev": sev or Severity.LOW, "title": "", "length": length,
            "content_type": "text/html"}


def test_parse_status_set():
    assert parse_status_set("301,302, 403") == {301, 302, 403}
    assert parse_status_set("") == set()
    assert parse_status_set("abc, 200") == {200}


def test_is_canonical_redirect():
    assert _is_canonical_redirect(_h("admin", 301, location="/admin/"))
    assert _is_canonical_redirect(_h("a/b", 308, location="/a/b/"))
    assert not _is_canonical_redirect(_h("x", 302, location="/login"))
    assert not _is_canonical_redirect(_h("x", 200))


def test_canonical_self_redirects_collapse_to_one_line():
    hits = [_h(f"dir{i}", 301, location=f"/dir{i}/") for i in range(30)]
    fs = make_findings("10.0.0.5:80", hits, wildcard_min=8)
    titles = [f.title for f in fs]
    # no per-path "Redirects to ..." finding; just one noise summary
    assert not any(t.startswith("Redirects to") for t in titles)
    noise = [f for f in fs if f.title == "Wildcard/noise responses suppressed"]
    assert len(noise) == 1 and "30×" in noise[0].evidence


def test_onsite_redirects_all_suppressed_bulk_or_distinct():
    # on-site redirects are app routing -> all noise, whether a bulk gate or a
    # lone distinct destination. Nothing is reported as a "Redirects to" finding.
    hits = [_h(f"p{i}", 302, location="/login") for i in range(20)]   # gate
    hits.append(_h("legacy", 302, location="/v2/home"))              # distinct
    fs = make_findings("10.0.0.5:80", hits, wildcard_min=8)
    titles = [f.title for f in fs]
    assert not any(t.startswith("Redirects to") for t in titles)
    assert not any(t.startswith("Off-site redirect") for t in titles)
    noise = [f for f in fs if f.title == "Wildcard/noise responses suppressed"]
    assert noise and "redirects to /login" in noise[0].evidence
    assert "redirects to /v2/home" in noise[0].evidence


def test_waf_403_flood_suppressed_small_group_kept():
    flood = [_h(f"q{i}", 403) for i in range(25)]
    fs = make_findings("10.0.0.5:80", flood, wildcard_min=8)
    assert not any("HTTP 403" in f.title for f in fs)
    assert any(f.title == "Wildcard/noise responses suppressed" for f in fs)
    # a handful of 403s is a real signal -> kept
    few = [_h(f"r{i}", 403) for i in range(3)]
    fs2 = make_findings("10.0.0.5:80", few, wildcard_min=8)
    assert any("HTTP 403" in f.title for f in fs2)


def test_filter_status_hard_drops_everywhere():
    hits = [_h("x", 302, location="/login"),
            _h("admin", 403, category="admin", sev=None)]   # sensitive 403
    fs = make_findings("10.0.0.5:80", hits, filter_status={302, 403})
    # 302 gone AND the sensitive-path 403 gone (hard drop is literal)
    assert not fs or all(f.category == "content-noise" for f in fs)
    assert not any("403" in (f.evidence or "") for f in fs)


def test_high_value_redirect_still_reported():
    # a redirect on a sensitive path is NOT generic -> keeps its own finding
    from ..models import Severity
    hits = [_h("admin", 302, location="/login", category="admin",
               sev=Severity.MEDIUM)]
    fs = make_findings("10.0.0.5:80", hits, wildcard_min=8)
    assert any(f.category == "content-admin" for f in fs)


def test_ferox_build_argv_adds_filter_status_at_source():
    argv = FeroxbusterAdapter().build_argv(
        "http://10.0.0.5/", "/tmp/wl.txt", filter_status={301, 302, 403})
    i = argv.index("--filter-status")
    codes = argv[i + 1]
    assert "301" in codes and "302" in codes and "403" in codes
    assert "404" in codes                      # defaults preserved


def _run_all():
    fns = [v for k, v in globals().items() if k.startswith("test_")]
    for fn in fns:
        fn()
        print(f"  ok  {fn.__name__}")
    print(f"\n{len(fns)}/{len(fns)} tests passed")


if __name__ == "__main__":
    _run_all()

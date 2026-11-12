"""Wildcard-redirect suppression: baseline random paths and hand feroxbuster
a --filter-size so it doesn't scan the whole wordlist on identical garbage.

Run: python -m netassess.tests.test_wildcard
"""
from __future__ import annotations

from ..adapters.feroxbuster_adapter import FeroxbusterAdapter
from ..config import Config
from ..engine import AssessmentEngine
from ..models import HTTPService
from .. import webfetch as _wf


def test_build_argv_includes_filter_size():
    argv = FeroxbusterAdapter().build_argv("http://h/", "wl.txt",
                                           filter_sizes=[162, 0])
    # one -S per size
    idxs = [i for i, a in enumerate(argv) if a == "-S"]
    vals = {argv[i + 1] for i in idxs}
    assert vals == {"162", "0"}


def _engine():
    return AssessmentEngine(Config(targets=["10.0.0.5"], show_progress=False))


def _svc():
    return HTTPService(url="http://10.0.0.5/", ip="10.0.0.5", port=80, scheme="http")


def test_wildcard_detected_returns_size(monkeypatch=None):
    eng = _engine()
    # every random path -> 302 with the same length 162
    orig = _wf.fetch
    _wf.fetch = lambda *a, **k: (302, {"content-length": "162"}, "")
    try:
        sizes = eng._wildcard_sizes(_svc())
    finally:
        _wf.fetch = orig
    assert sizes == [162]


def test_no_wildcard_when_sizes_differ():
    eng = _engine()
    seq = iter([(302, {"content-length": "162"}, ""),
                (302, {"content-length": "999"}, ""),
                (404, {}, "x")])
    orig = _wf.fetch
    _wf.fetch = lambda *a, **k: next(seq)
    try:
        sizes = eng._wildcard_sizes(_svc())
    finally:
        _wf.fetch = orig
    assert sizes == []          # inconsistent -> no wildcard filter


def test_no_wildcard_on_normal_404():
    eng = _engine()
    orig = _wf.fetch
    _wf.fetch = lambda *a, **k: (404, {}, "not found")  # 404 is not 'present'
    try:
        assert eng._wildcard_sizes(_svc()) == []
    finally:
        _wf.fetch = orig


def _run_all():
    fns = [v for k, v in globals().items() if k.startswith("test_")]
    for fn in fns:
        fn()
        print(f"  ok  {fn.__name__}")
    print(f"\n{len(fns)}/{len(fns)} tests passed")


if __name__ == "__main__":
    _run_all()

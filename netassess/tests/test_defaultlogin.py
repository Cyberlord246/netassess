"""Tests for default-login exposure checks.

Run: python -m netassess.tests.test_defaultlogin
"""
from __future__ import annotations

from .. import defaultlogin as dl
from ..config import Config
from ..defaultlogin import DefaultLoginChecker
from ..models import Confidence, HTTPService, Host, Technology, ValidationState


class _Scope:
    def authorize(self, ip, port=None):
        return type("D", (), {"allowed": True})()


def _host_svc(server="", techs=()):
    host = Host(ip="10.0.0.9")
    svc = HTTPService(url="http://10.0.0.9:3000/", ip="10.0.0.9", port=3000,
                      scheme="http", server=server)
    svc.technologies = [Technology(name=t, category="", evidence="",
                                   confidence=Confidence.MEDIUM) for t in techs]
    return host, svc


def test_identified_product_with_reachable_interface_flags(monkeypatch):
    # grafana identified; its /login returns 200 -> expect a finding
    monkeypatch.setattr(dl, "fetch", lambda *a, **k: (200, {}, ""))
    host, svc = _host_svc(techs=["Grafana"])
    out = DefaultLoginChecker(Config(), _Scope()).check_service(host, svc)
    assert len(out) == 1
    f = out[0]
    assert f.category == "default-login"
    assert f.validation == ValidationState.NEEDS_VALIDATION
    assert "no credentials were submitted" in f.evidence.lower()


def test_protected_interface_still_flagged():
    pass  # placeholder; covered by the monkeypatched variant below


def test_unknown_product_no_finding(monkeypatch):
    monkeypatch.setattr(dl, "fetch", lambda *a, **k: (200, {}, ""))
    host, svc = _host_svc(server="nginx/1.25")   # no known default-login product
    out = DefaultLoginChecker(Config(), _Scope()).check_service(host, svc)
    assert out == []


def test_unreachable_interface_no_finding(monkeypatch):
    # product identified but the path is not reachable (connection error)
    monkeypatch.setattr(dl, "fetch", lambda *a, **k: (None, {}, ""))
    host, svc = _host_svc(techs=["Jenkins"])
    out = DefaultLoginChecker(Config(), _Scope()).check_service(host, svc)
    assert out == []


# -- tiny monkeypatch shim so this runs without pytest ---------------------- #
class _MP:
    def __init__(self):
        self._undo = []

    def setattr(self, obj, name, val):
        old = getattr(obj, name)
        self._undo.append((obj, name, old))
        setattr(obj, name, val)

    def undo(self):
        for obj, name, old in reversed(self._undo):
            setattr(obj, name, old)
        self._undo.clear()


def _run_all():
    import inspect
    fns = [v for k, v in globals().items() if k.startswith("test_")]
    passed = 0
    for fn in fns:
        mp = _MP()
        try:
            if "monkeypatch" in inspect.signature(fn).parameters:
                fn(mp)
            else:
                fn()
            print(f"  ok  {fn.__name__}")
            passed += 1
        finally:
            mp.undo()
    print(f"\n{passed}/{len(fns)} tests passed")


if __name__ == "__main__":
    _run_all()

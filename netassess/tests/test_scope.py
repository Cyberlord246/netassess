"""Tests for the safety-critical Scope Engine and target parsing.

Run: python -m netassess.tests.test_scope   (or with pytest)
"""
from __future__ import annotations

from ..config import Config
from ..scope import ScopeEngine, Verdict, parse_targets


def _engine(targets, exclude=None, forbidden=None):
    cfg = Config(targets=targets, exclude=exclude or [],
                 forbidden_ports=forbidden or [])
    return ScopeEngine(cfg)


def test_parse_ip_and_cidr():
    nets, errors = parse_targets(["192.0.2.10", "192.0.2.0/24", "bad"])
    assert not any("192.0.2.0/24" == str(n) for n in nets) is False  # present
    assert str(nets[0]) == "192.0.2.10/32"
    assert len(errors) == 1 and "bad" in errors[0]


def test_dedup():
    nets, _ = parse_targets(["192.0.2.10", "192.0.2.10", "192.0.2.10/32"])
    assert len(nets) == 1


def test_in_scope_allow():
    eng = _engine(["192.0.2.0/24"])
    assert eng.authorize("192.0.2.55").verdict is Verdict.ALLOW


def test_out_of_scope_deny():
    eng = _engine(["192.0.2.0/24"])
    d = eng.authorize("203.0.113.5")
    assert d.verdict is Verdict.DENY and "outside" in d.reason


def test_exclusion_wins():
    eng = _engine(["192.0.2.0/24"], exclude=["192.0.2.55"])
    assert eng.authorize("192.0.2.55").verdict is Verdict.DENY


def test_forbidden_port():
    eng = _engine(["192.0.2.0/24"], forbidden=[3389])
    assert eng.authorize("192.0.2.5", 3389).verdict is Verdict.DENY
    assert eng.authorize("192.0.2.5", 443).verdict is Verdict.ALLOW


def test_discovered_host_not_auto_authorized():
    # A host outside the original include list must never be authorized,
    # even if "discovered" later.
    eng = _engine(["192.0.2.0/30"])
    assert eng.authorize("198.51.100.99").verdict is Verdict.DENY


def test_expand_hosts_respects_exclusions():
    eng = _engine(["192.0.2.0/30"], exclude=["192.0.2.1"])
    hosts = eng.expand_hosts()
    assert "192.0.2.1" not in hosts
    assert "192.0.2.2" in hosts


def test_decision_log():
    eng = _engine(["192.0.2.0/24"])
    eng.authorize("192.0.2.5")
    eng.authorize("8.8.8.8")
    assert len(eng.decisions) == 2
    assert len(eng.denied_decisions()) == 1


def _run_all():
    fns = [v for k, v in globals().items() if k.startswith("test_")]
    passed = 0
    for fn in fns:
        fn()
        passed += 1
        print(f"  ok  {fn.__name__}")
    print(f"\n{passed}/{len(fns)} tests passed")


if __name__ == "__main__":
    _run_all()

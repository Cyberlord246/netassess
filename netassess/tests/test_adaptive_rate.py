"""Adaptive rate backoff: penalize cuts the effective rate, then it recovers.

Run: python -m netassess.tests.test_adaptive_rate
"""
from __future__ import annotations

import time

from ..config import Config
from ..scope import ScopeEngine, TokenBucket


def test_penalize_cuts_effective_rate():
    b = TokenBucket(rate=1000.0)
    now = time.monotonic()
    assert b._eff_rate(now) == 1000.0
    b.penalize()                       # halve
    assert b._eff_rate(time.monotonic()) <= 500.0 + 1


def test_repeated_penalize_bounded():
    b = TokenBucket(rate=1000.0)
    for _ in range(20):
        b.penalize()
    # never below the floor (5% of configured)
    assert b._eff_rate(time.monotonic()) >= 1000.0 * b._MIN_MULT - 1


def test_recovers_toward_full_over_time():
    b = TokenBucket(rate=1000.0)
    b.penalize()
    b._recover_s = 0.0001              # make recovery effectively instant
    time.sleep(0.01)
    assert b._eff_rate(time.monotonic()) >= 999.0


def test_scope_note_overload_respects_flag():
    # disabled -> penalize must NOT be called
    cfg = Config(targets=["192.0.2.10"], adaptive_rate=False)
    sc = ScopeEngine(cfg)
    before = sc._bucket._eff_rate(time.monotonic())
    sc.note_overload()
    assert sc._bucket._eff_rate(time.monotonic()) == before
    # enabled -> backs off
    cfg2 = Config(targets=["192.0.2.10"], adaptive_rate=True, rate=1000.0)
    sc2 = ScopeEngine(cfg2)
    sc2.note_overload()
    assert sc2._bucket._eff_rate(time.monotonic()) < 1000.0


def _run_all():
    fns = [v for k, v in globals().items() if k.startswith("test_")]
    for fn in fns:
        fn()
        print(f"  ok  {fn.__name__}")
    print(f"\n{len(fns)}/{len(fns)} tests passed")


if __name__ == "__main__":
    _run_all()

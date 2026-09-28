"""Tests for the live progress reporter.

Verifies the staged plan, per-stage RUNNING/DONE markers, and the
'done/total - remaining' item counter (including the thread-safe bump path).
ASCII-only output is asserted so legacy Windows consoles stay safe.

Run: python -m netassess.tests.test_progress
"""
from __future__ import annotations

import io

from ..progress import Progress


def _p():
    buf = io.StringIO()
    return Progress(out=buf, enabled=True), buf


def test_plan_lists_all_stages():
    p, buf = _p()
    p.set_plan(["Discovery", "Port scan", "Probes"])
    out = buf.getvalue()
    assert "Assessment plan - 3 stage(s)" in out
    assert "1/3  Discovery" in out and "3/3  Probes" in out


def test_stage_markers():
    p, buf = _p()
    p.set_plan(["A", "B"])
    p.stage_start(1, "A")
    p.stage_done(1, "A", "2 live host(s)")
    out = buf.getvalue()
    assert "[1/2] A ... RUNNING" in out
    assert "[1/2] A ... DONE (2 live host(s))" in out


def test_items_shows_remaining():
    p, buf = _p()
    p.set_plan(["A"])
    buf.truncate(0); buf.seek(0)
    p.items(3, 10, "web services")
    out = buf.getvalue()
    assert "web services: 3/10 (30%) - 7 remaining" in out


def test_items_newline_on_complete():
    p, buf = _p()
    p.items(10, 10, "x")
    assert buf.getvalue().rstrip().endswith("0 remaining")
    assert buf.getvalue().endswith("\n")


def test_bump_counts_up_to_total():
    p, buf = _p()
    p.reset_counter()
    for _ in range(5):
        p.bump(5, "services tested")
    out = buf.getvalue()
    assert "5/5 (100%) - 0 remaining" in out


def test_disabled_writes_nothing():
    buf = io.StringIO()
    p = Progress(out=buf, enabled=False)
    p.set_plan(["A", "B"])
    p.stage_start(1, "A")
    p.items(1, 2, "x")
    assert buf.getvalue() == ""


def test_output_is_ascii():
    p, buf = _p()
    p.set_plan(["Discovery", "Validation"])
    p.stage_start(1, "Discovery")
    p.items(1, 3, "services")
    p.stage_done(1, "Discovery", "ok")
    buf.getvalue().encode("ascii")   # raises if any non-ASCII char slipped in


def _run_all():
    fns = [v for k, v in sorted(globals().items()) if k.startswith("test_")]
    for fn in fns:
        fn()
        print(f"  ok  {fn.__name__}")
    print(f"\n{len(fns)}/{len(fns)} tests passed")


if __name__ == "__main__":
    _run_all()

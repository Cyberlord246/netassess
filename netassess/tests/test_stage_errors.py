"""The pipeline must report a stage failure, not silently continue as if done.

Run: python -m netassess.tests.test_stage_errors
"""
from __future__ import annotations

import tempfile

from ..config import Config
from ..engine import AssessmentEngine

_NOOP_PHASES = [
    "_phase_discovery", "_phase_rdns", "_phase_portscan", "_phase_service_id",
    "_phase_probe", "_phase_default_login", "_phase_endpoints",
    "_phase_domains", "_phase_roles",
]


def _engine():
    cfg = Config(targets=["192.0.2.10"], show_progress=False,
                 output_dir=tempfile.mkdtemp(prefix="na-test-"),
                 cve_enabled=False, validate=False, vhost_probe=False,
                 content_discovery=False)
    eng = AssessmentEngine(cfg)
    for name in _NOOP_PHASES:
        setattr(eng, name, lambda *a, **k: None)
    return eng


def test_failing_stage_is_recorded_and_pipeline_continues():
    eng = _engine()
    ran_after = {"roles": False}

    def boom():
        raise RuntimeError("synthetic failure")

    def after():
        ran_after["roles"] = True

    eng._phase_vuln = boom          # a mid-pipeline stage blows up
    eng._phase_roles = after        # a later, independent stage

    graph = eng.run()

    errs = graph.meta.get("stage_errors") or {}
    assert "Vulnerability heuristics" in errs, errs
    assert "synthetic failure" in errs["Vulnerability heuristics"]
    # pipeline did NOT abort — a later independent stage still executed
    assert ran_after["roles"] is True


def test_clean_run_has_no_stage_errors():
    eng = _engine()
    graph = eng.run()
    assert graph.meta.get("stage_errors") == {}


def _run_all():
    fns = [v for k, v in globals().items() if k.startswith("test_")]
    for fn in fns:
        fn()
        print(f"  ok  {fn.__name__}")
    print(f"\n{len(fns)}/{len(fns)} tests passed")


if __name__ == "__main__":
    _run_all()

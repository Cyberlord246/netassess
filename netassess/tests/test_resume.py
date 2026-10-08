"""Resume skips stages already completed in a prior state.json.

Run: python -m netassess.tests.test_resume
"""
from __future__ import annotations

import tempfile

from ..config import Config
from ..engine import AssessmentEngine

_NOOP = ["_phase_discovery", "_phase_rdns", "_phase_portscan",
         "_phase_service_id", "_phase_probe", "_phase_default_login",
         "_phase_endpoints", "_phase_domains", "_phase_roles"]


def _engine(out, resume=False):
    cfg = Config(targets=["192.0.2.10"], show_progress=False, output_dir=out,
                 cve_enabled=False, validate=False, vhost_probe=False,
                 content_discovery=False, resume=resume)
    eng = AssessmentEngine(cfg)
    for n in _NOOP:
        setattr(eng, n, lambda *a, **k: None)
    return eng


def test_completed_stages_recorded_then_skipped():
    out = tempfile.mkdtemp(prefix="na-res-")
    # first run records completed stages
    eng1 = _engine(out)
    calls = {"vuln": 0}
    eng1._phase_vuln = lambda: calls.__setitem__("vuln", calls["vuln"] + 1)
    g1 = eng1.run()
    assert "Vulnerability heuristics" in g1.meta["completed_stages"]
    assert calls["vuln"] == 1

    # second run with --resume: the completed stage must NOT execute again
    eng2 = _engine(out, resume=True)
    ran = {"vuln": 0}
    eng2._phase_vuln = lambda: ran.__setitem__("vuln", ran["vuln"] + 1)
    eng2.run()
    assert ran["vuln"] == 0          # skipped via resume


def test_without_resume_everything_runs():
    out = tempfile.mkdtemp(prefix="na-res2-")
    _engine(out).run()              # seed a state.json
    eng = _engine(out, resume=False)
    ran = {"vuln": 0}
    eng._phase_vuln = lambda: ran.__setitem__("vuln", ran["vuln"] + 1)
    eng.run()
    assert ran["vuln"] == 1          # no resume -> runs again


def _run_all():
    fns = [v for k, v in globals().items() if k.startswith("test_")]
    for fn in fns:
        fn()
        print(f"  ok  {fn.__name__}")
    print(f"\n{len(fns)}/{len(fns)} tests passed")


if __name__ == "__main__":
    _run_all()

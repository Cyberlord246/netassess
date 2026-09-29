"""Tests for scan profile presets.

Run: python -m netassess.tests.test_profiles
"""
from __future__ import annotations

from ..cli import build_parser, _build_config
from ..config import COMMON_PORTS
from ..profiles import PROFILES, DEFAULT_PROFILE, apply_profile, profile_names


def _cfg(argv):
    args = build_parser().parse_args(argv)
    return args, _build_config(args)


def test_standard_is_default_and_noop():
    args, cfg = _cfg(["scan", "--targets", "192.0.2.10"])
    assert args.profile == DEFAULT_PROFILE == "standard"
    assert args._profile_applied == []
    # unchanged from platform defaults: top-1000+, no content/nuclei
    assert len(cfg.effective_ports()) > 100
    assert cfg.content_discovery is False
    assert cfg.nuclei is False


def test_quick_uses_common_ports():
    args, cfg = _cfg(["scan", "--targets", "192.0.2.10", "--profile", "quick"])
    assert "common_ports" in args._profile_applied
    assert len(cfg.effective_ports()) == len(COMMON_PORTS)


def test_deep_enables_thorough_options():
    _, cfg = _cfg(["scan", "--targets", "192.0.2.10", "--profile", "deep"])
    assert cfg.service_detection == "deep"
    assert cfg.deep is True
    assert cfg.content_discovery is True
    assert cfg.nuclei is True


def test_web_focuses_on_web_surface():
    _, cfg = _cfg(["scan", "--targets", "192.0.2.10", "--profile", "web"])
    assert cfg.skip_portscan is True
    assert cfg.content_discovery is True
    assert cfg.vhost_probe is True
    assert cfg.reverse_dns is False


def test_explicit_flag_overrides_profile():
    # quick wants ~40 common ports; an explicit --ports must win
    _, cfg = _cfg(["scan", "--targets", "192.0.2.10", "--profile", "quick",
                   "--ports", "1-1024"])
    assert len(cfg.effective_ports()) == 1024


def test_apply_profile_only_fills_unset():
    args = build_parser().parse_args(
        ["scan", "--targets", "192.0.2.10", "--content-discovery"])
    # content_discovery already True from the user; deep must not "re-apply" it
    applied = apply_profile(args, "deep")
    assert "content_discovery" not in applied
    assert "deep" in applied and "nuclei" in applied


def test_every_profile_is_applyable():
    for name in profile_names():
        args = build_parser().parse_args(["scan", "--targets", "192.0.2.10"])
        apply_profile(args, name)   # must not raise
        assert "_desc" in PROFILES[name]


def _run_all():
    fns = [v for k, v in globals().items() if k.startswith("test_")]
    for fn in fns:
        fn()
        print(f"  ok  {fn.__name__}")
    print(f"\n{len(fns)}/{len(fns)} tests passed")


if __name__ == "__main__":
    _run_all()

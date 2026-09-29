"""Scan profiles — one-flag presets that bundle sensible option combinations.

The platform exposes ~40 individual knobs. Most users want one of a handful of
well-known trade-offs (fast triage vs. thorough audit vs. web-app focus) rather
than hand-picking flags. A *profile* is a named bundle applied with a single
``--profile NAME`` flag.

Design contract
---------------
* A profile only ever *fills in* options the user did not set explicitly, so an
  explicit flag always wins over the profile (e.g. ``--profile quick --ports
  1-1024`` uses ``1-1024``). We implement this by mutating the parsed ``args``
  object *before* :func:`netassess.cli._build_config` reads it, touching only
  attributes still at their default (falsy / ``None``). All existing precedence
  logic in ``_build_config`` then applies unchanged.
* ``standard`` is the default and sets nothing — it *is* the platform's
  out-of-the-box behavior, so existing invocations are unaffected.
* Profiles never relax safety: they only toggle non-destructive, already-safe
  options that a user could set by hand.
* Keys must be argument ``dest`` names that exist in ``_add_scan_args``.
"""
from __future__ import annotations

# Web ports for the web-app profile (defined here since the scan does not have a
# dedicated web-port flag). Kept small and high-signal.
WEB_PORTS = "80,443,8080,8443,8000,8888,8008,8081,3000,5000,9000,9443"

# Each profile maps CLI ``args`` attribute names to the value the profile wants.
# The special ``_desc`` key is human-facing help text (not applied to args).
PROFILES: dict[str, dict] = {
    "quick": {
        "_desc": "Fast triage — ~40 high-signal ports, banner service ID, CVE. "
                 "No content discovery or nuclei. Best for a first look or a "
                 "large scope.",
        "common_ports": True,
    },
    "standard": {
        "_desc": "Balanced default — Nmap top-1000 ports, service/version ID, "
                 "protocol probes, TLS analysis, CVE correlation.",
        # Intentionally empty: standard == the platform's built-in defaults.
    },
    "deep": {
        "_desc": "Thorough audit — top-1000 ports, deep service/version "
                 "detection, content discovery, and nuclei (if installed). "
                 "Slower; more requests per host.",
        "deep": True,
        "content_discovery": True,
        "nuclei": True,
    },
    "web": {
        "_desc": "Web-app focus — common web ports, content discovery, and "
                 "nuclei (if installed). Virtual-host discovery is already on "
                 "by default.",
        "ports": WEB_PORTS,
        "content_discovery": True,
        "nuclei": True,
    },
}

DEFAULT_PROFILE = "standard"


def profile_names() -> list[str]:
    """Profile names in a stable, presentation order."""
    order = ["quick", "standard", "deep", "web"]
    return [n for n in order if n in PROFILES] + \
           [n for n in PROFILES if n not in order]


def describe(name: str) -> str:
    """One-line human description of a profile."""
    return PROFILES.get(name, {}).get("_desc", "")


def help_text() -> str:
    """Multi-line ``--profile`` help listing every profile."""
    lines = ["preset bundle of options (an explicit flag always overrides it):"]
    for name in profile_names():
        lines.append(f"  {name:9s} {describe(name)}")
    return "\n".join(lines)


def apply_profile(args, name: str) -> list[str]:
    """Fill in profile defaults on ``args`` without clobbering explicit flags.

    Returns the list of attribute names the profile actually set (for a concise
    "this preset enabled X, Y" line in the scan banner). Only attributes still
    at their falsy/``None`` default are touched, so anything the user passed on
    the command line takes precedence.
    """
    spec = PROFILES.get(name)
    if not spec:
        raise KeyError(name)
    applied: list[str] = []
    for key, value in spec.items():
        if key.startswith("_"):
            continue
        current = getattr(args, key, None)
        if current:          # user set this explicitly (truthy) -> keep theirs
            continue
        setattr(args, key, value)
        applied.append(key)
    return applied

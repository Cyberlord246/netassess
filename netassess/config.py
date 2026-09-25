"""Configuration and policy for the assessment platform.

A single ``Config`` object carries every knob the CLI exposes and every policy
the Scope/Policy engines enforce. Nothing in the platform performs a network
action without a Config in hand.
"""
from __future__ import annotations

import json
from dataclasses import dataclass, field, asdict
from typing import Optional

from .data_ports import COMMON_40, TOP_1000_TCP

# The default scan set is now the canonical Nmap top-1000 TCP ports (good
# coverage without needing nmap installed). COMMON_40 remains available as a
# fast, high-signal preset via --common-ports.
DEFAULT_PORTS = list(TOP_1000_TCP)
COMMON_PORTS = list(COMMON_40)


@dataclass
class Config:
    # --- targets & scope --------------------------------------------------
    targets: list[str] = field(default_factory=list)   # raw IP/CIDR strings
    exclude: list[str] = field(default_factory=list)   # raw IP/CIDR strings

    # --- mode -------------------------------------------------------------
    mode: str = "deterministic"       # deterministic | ai | auto

    # --- port scanning ----------------------------------------------------
    ports: list[int] = field(default_factory=lambda: list(DEFAULT_PORTS))
    full_port_scan: bool = False      # 1-65535 when True
    service_detection: str = "banner"  # off | banner | deep

    # --- performance / safety limits -------------------------------------
    concurrency: int = 50             # max simultaneous sockets
    rate: float = 200.0               # max new connections / second (token bucket)
    timeout: float = 3.0              # per-connection timeout (s)
    retries: int = 1                  # extra attempts on transient failure

    # --- discovery --------------------------------------------------------
    discovery_ports: list[int] = field(default_factory=lambda: [443, 80, 22, 445, 3389])
    skip_discovery: bool = False      # treat all in-scope hosts as live

    # --- udp --------------------------------------------------------------
    udp_scan: bool = False            # scan common UDP ports (opt-in)
    udp_ports: list[int] = field(
        default_factory=lambda: [53, 123, 161, 137, 500, 1900, 5353, 69, 111, 623])

    # --- policy: forbidden ports (never touched even if requested) --------
    forbidden_ports: list[int] = field(default_factory=list)

    # --- output -----------------------------------------------------------
    output_dir: str = "netassess-out"
    state_file: str = "state.json"

    # --- cve --------------------------------------------------------------
    cve_enabled: bool = True          # run offline CVE correlation
    cve_online: bool = False          # enrich via NVD (network, opt-in)
    cve_db: Optional[str] = None      # extra CVE JSON to merge into the KB
    cve_nvd_cache: Optional[str] = None  # offline NVD sync cache (default ~/.netassess/nvd.json)
    kev_cache: Optional[str] = None   # CISA KEV + EPSS cache (default ~/.netassess/kev.json)

    # --- content discovery ------------------------------------------------
    content_discovery: bool = False   # probe common web paths (GET-only, opt-in)
    content_wordlist: Optional[str] = None  # extra paths to append to the builtin set
    content_quick: bool = False       # use only the small curated list (~70 paths)
    content_tool: str = "auto"        # auto | feroxbuster | builtin
    content_depth: int = 2            # feroxbuster recursion depth
    content_extensions: str = ""      # e.g. "php,bak,zip,sql" (feroxbuster -x)
    content_thorough: bool = False    # feroxbuster: collect extensions + backups

    # --- virtual-host probing ---------------------------------------------
    vhost_probe: bool = False          # probe TLS SAN/CN hostnames as vhosts (in-scope)

    # --- nuclei -----------------------------------------------------------
    nuclei: bool = False               # run nuclei against discovered URLs (if installed)
    nuclei_thorough: bool = False      # relax the light template filter
    nuclei_rate: int = 30              # nuclei requests/sec cap

    # --- report -----------------------------------------------------------
    html_report: bool = True          # also emit report.html
    report_min_severity: str = "medium"  # suppress findings below this in reports
    report_aggregate: bool = True     # collapse same finding across hosts into one

    # --- ai ---------------------------------------------------------------
    ai_provider: str = "none"         # none | anthropic | ...
    ai_model: str = "claude-opus-4-8"
    ai_max_steps: int = 40

    # --- misc -------------------------------------------------------------
    deep: bool = False                # enable heavier (still safe) probes

    def effective_ports(self) -> list[int]:
        if self.full_port_scan:
            base = list(range(1, 65536))
        else:
            base = list(self.ports)
        forbidden = set(self.forbidden_ports)
        return [p for p in base if p not in forbidden]

    def to_dict(self) -> dict:
        return asdict(self)

    @classmethod
    def from_file(cls, path: str) -> "Config":
        with open(path, "r", encoding="utf-8") as fh:
            data = json.load(fh)
        return cls(**data)

    def save(self, path: str) -> None:
        with open(path, "w", encoding="utf-8") as fh:
            json.dump(self.to_dict(), fh, indent=2)

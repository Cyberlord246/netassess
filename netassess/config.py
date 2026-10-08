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

# Ports that a dedicated prober / high-value check exists for — these MUST always
# be in the default scan set, even if they fall outside Nmap's top-1000 (e.g.
# Redis 6379, MongoDB 27017, Memcached 11211 are not in the top-1000 but the tool
# has unauthenticated-exposure checks for them).
PROBER_PORTS = {
    21, 22, 23, 25, 53, 80, 110, 111, 135, 139, 143, 161, 389, 443, 445, 465,
    587, 636, 873, 993, 995, 1433, 1521, 2049, 2375, 2376, 3306, 3389, 5432,
    5900, 5901, 5902, 5903, 5985, 5986, 6379, 8000, 8080, 8443, 8888, 9200,
    9300, 11211, 27017,
}

# Default scan set = Nmap top-1000 UNION every prober-relevant port, so the tool
# never misses a service it can actually assess. COMMON_40 stays as the fast
# --common-ports preset.
DEFAULT_PORTS = sorted(set(TOP_1000_TCP) | set(COMMON_40) | PROBER_PORTS)
COMMON_PORTS = list(COMMON_40)

# Safe default set when the port scan is SKIPPED and the operator gave no
# explicit --ports — prevents assuming all ~1000 ports open on every host.
WEB_PORTS = [80, 443, 8080, 8443, 8000, 8888, 8008, 8081, 3000, 5000, 9000, 9443]


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
    skip_portscan: bool = False       # assume `ports` open, probe directly (no scan)
    service_detection: str = "banner"  # off | banner | deep

    # --- performance / safety limits -------------------------------------
    concurrency: int = 50             # max simultaneous sockets
    rate: float = 200.0               # max new connections / second (token bucket)
    timeout: float = 3.0              # per-connection timeout ceiling (s)
    retries: int = 1                  # extra attempts on transient failure

    # adaptive timeout: derive a tighter per-host timeout from the host's RTT
    # (measured during discovery), so fast hosts don't wait the full ceiling on
    # every filtered port. Bounded by [adaptive_floor, timeout].
    adaptive_timeout: bool = True
    adaptive_factor: float = 10.0     # effective timeout = rtt * factor
    adaptive_floor: float = 0.3       # never go below this (s)

    # --- discovery --------------------------------------------------------
    discovery_ports: list[int] = field(default_factory=lambda: [443, 80, 22, 445, 3389])
    skip_discovery: bool = False      # treat all in-scope hosts as live
    discovery_mode: str = "auto"      # auto | nmap | tcp
    #  auto : nmap -sn if available (+ TCP fallback for the rest), else TCP
    #  nmap : nmap -sn only
    #  tcp  : built-in pure-Python TCP-connect discovery only

    # --- smtp -------------------------------------------------------------
    smtp_relay_test: bool = True      # test SMTP open relay (non-destructive; aborts before DATA)

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

    # --- http probing -----------------------------------------------------
    http_tool: str = "auto"           # auto | httpx | builtin (bulk HTTP fingerprint)

    # --- content discovery ------------------------------------------------
    content_discovery: bool = False   # probe common web paths (GET-only, opt-in)
    content_wordlist: Optional[str] = None  # extra paths to append to the builtin set
    content_quick: bool = False       # use only the small curated list (~70 paths)
    content_tool: str = "auto"        # auto | feroxbuster | builtin
    content_depth: int = 2            # feroxbuster recursion depth
    content_extensions: str = ""      # e.g. "php,bak,zip,sql" (feroxbuster -x)
    content_thorough: bool = False    # feroxbuster: collect extensions + backups

    # --- validation & assessment ------------------------------------------
    validate: bool = True               # run the (non-destructive) validation layer
    validation_credentialed: bool = False  # opt-in credentialed confirmation (key-based SSH, read-only)
    auth_config: Optional[str] = None   # JSON: host -> {user, key, port} for credentialed checks

    # --- virtual-host probing ---------------------------------------------
    vhost_probe: bool = True            # probe TLS SAN/CN hostnames as vhosts (in-scope)

    # --- nuclei -----------------------------------------------------------
    nuclei: bool = False               # run nuclei against discovered URLs (if installed)
    nuclei_thorough: bool = False      # relax the light template filter
    nuclei_rate: int = 30              # nuclei requests/sec cap

    # --- report -----------------------------------------------------------
    html_report: bool = True          # also emit report.html
    report_min_severity: str = "info"  # show all severities (info+); raise with --min-severity
    report_aggregate: bool = True     # collapse same finding across hosts into one
    # low-signal finding titles hidden from the human report (still in report.json)
    report_suppress_titles: list[str] = field(default_factory=lambda: [
        "Missing HTTP security headers",
        "Software version disclosure via HTTP headers",
    ])

    # --- ai ---------------------------------------------------------------
    ai_provider: str = "none"         # none | anthropic | ...
    ai_model: str = "claude-opus-4-8"
    ai_max_steps: int = 40

    # --- misc -------------------------------------------------------------
    deep: bool = False                # enable heavier (still safe) probes
    show_progress: bool = True        # print the staged plan + live progress

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

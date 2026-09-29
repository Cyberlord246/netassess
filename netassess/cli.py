"""Command-line interface.

Examples
--------
    python -m netassess network scan --targets targets.txt --mode auto
    python -m netassess network scan --targets 192.0.2.10,192.0.2.20 --deep
    python -m netassess scope check --targets 10.0.0.0/24 --exclude 10.0.0.1
    python -m netassess report --state netassess-out/state.json
"""
from __future__ import annotations

import argparse
import os
import sys

from .config import Config, COMMON_PORTS, DEFAULT_PORTS
from .engine import AssessmentEngine
from .report import ReportGenerator
from .scope import ScopeEngine
from .state import AssetGraph


def _looks_like_ip_or_cidr(token: str) -> bool:
    import ipaddress
    try:
        if "/" in token:
            ipaddress.ip_network(token, strict=False)
        else:
            ipaddress.ip_address(token)
        return True
    except ValueError:
        return False


def _read_targets(value: str | None, is_file_hint: bool = False) -> list[str]:
    if not value:
        return []
    # file?
    if os.path.isfile(value):
        with open(value, "r", encoding="utf-8") as fh:
            return [ln.strip() for ln in fh if ln.strip() and not ln.startswith("#")]
    # comma list
    tokens = [x.strip() for x in value.split(",") if x.strip()]
    # Guard: a single token that is neither a valid IP/CIDR nor an existing file
    # almost always means the user pointed at a targets file that isn't there.
    # Fail loudly instead of silently treating the filename as a target.
    if len(tokens) == 1 and not _looks_like_ip_or_cidr(tokens[0]):
        raise FileNotFoundError(
            f"'{tokens[0]}' is neither a valid IP/CIDR nor an existing file.\n"
            f"       Current directory: {os.getcwd()}\n"
            f"       Provide a real file path (absolute is safest) or a "
            f"comma-separated list of IPs/CIDRs.")
    return tokens


def _parse_ports(spec: str | None) -> list[int] | None:
    if not spec:
        return None
    out: list[int] = []
    for part in spec.split(","):
        part = part.strip()
        if "-" in part:
            a, b = part.split("-", 1)
            out.extend(range(int(a), int(b) + 1))
        elif part:
            out.append(int(part))
    return sorted(set(out))


def _build_config(args) -> Config:
    cfg = Config()
    cfg.targets = _read_targets(getattr(args, "targets", None))
    cfg.exclude = _read_targets(getattr(args, "exclude", None))
    cfg.mode = getattr(args, "mode", "deterministic")
    ports = _parse_ports(getattr(args, "ports", None))
    if ports:                                   # explicit --ports wins
        cfg.ports = ports
    elif getattr(args, "common_ports", False):  # fast 40-port preset
        cfg.ports = list(COMMON_PORTS)
    # else: keep the default (top-1000 TCP)
    cfg.full_port_scan = getattr(args, "full_port_scan", False)
    cfg.deep = getattr(args, "deep", False)
    if cfg.deep:
        cfg.service_detection = "deep"
    if getattr(args, "concurrency", None):
        cfg.concurrency = args.concurrency
    if getattr(args, "rate", None):
        cfg.rate = args.rate
    if getattr(args, "timeout", None):
        cfg.timeout = args.timeout
    if getattr(args, "retries", None) is not None:
        cfg.retries = args.retries
    if getattr(args, "no_adaptive_timeout", False):
        cfg.adaptive_timeout = False
    if getattr(args, "discovery", None):
        cfg.discovery_mode = args.discovery
    if getattr(args, "skip_discovery", False):
        cfg.skip_discovery = True
    if getattr(args, "skip_portscan", False):
        cfg.skip_portscan = True
    if getattr(args, "output", None):
        cfg.output_dir = args.output
    if getattr(args, "ai_provider", None):
        cfg.ai_provider = args.ai_provider
    if getattr(args, "no_cve", False):
        cfg.cve_enabled = False
    if getattr(args, "cve_online", False):
        cfg.cve_online = True
    if getattr(args, "cve_db", None):
        cfg.cve_db = args.cve_db
    if getattr(args, "no_smtp_relay_test", False):
        cfg.smtp_relay_test = False
    if getattr(args, "udp", False):
        cfg.udp_scan = True
    udp_ports = _parse_ports(getattr(args, "udp_ports", None))
    if udp_ports:
        cfg.udp_ports = udp_ports
    if getattr(args, "no_vhosts", False):
        cfg.vhost_probe = False
    if getattr(args, "no_validate", False):
        cfg.validate = False
    if getattr(args, "no_progress", False):
        cfg.show_progress = False
    if getattr(args, "auth_config", None):
        cfg.auth_config = args.auth_config
        cfg.validation_credentialed = True
    if getattr(args, "nuclei", False):
        cfg.nuclei = True
    if getattr(args, "nuclei_thorough", False):
        cfg.nuclei = True
        cfg.nuclei_thorough = True
    if getattr(args, "nuclei_rate", None):
        cfg.nuclei_rate = args.nuclei_rate
    if getattr(args, "content_discovery", False):
        cfg.content_discovery = True
    if getattr(args, "wordlist", None):
        cfg.content_wordlist = args.wordlist
    if getattr(args, "content_quick", False):
        cfg.content_quick = True
    if getattr(args, "content_tool", None):
        cfg.content_tool = args.content_tool
    if getattr(args, "content_depth", None):
        cfg.content_depth = args.content_depth
    if getattr(args, "content_extensions", None):
        cfg.content_extensions = args.content_extensions
    if getattr(args, "content_thorough", False):
        cfg.content_thorough = True
    if getattr(args, "no_html", False):
        cfg.html_report = False
    if getattr(args, "all_findings", False):
        cfg.report_min_severity = "info"
    elif getattr(args, "min_severity", None):
        cfg.report_min_severity = args.min_severity
    if getattr(args, "no_aggregate", False):
        cfg.report_aggregate = False
    if getattr(args, "include_noise", False):
        cfg.report_suppress_titles = []
    return cfg


def _logger(verbose: bool):
    def log(*a, **k):
        print(*a, **k)
    return log if verbose else (lambda *a, **k: print(*a, **k))


# --------------------------------------------------------------------------- #
# subcommands
# --------------------------------------------------------------------------- #
def cmd_scan(args) -> int:
    cfg = _build_config(args)
    if not cfg.targets:
        print("error: no targets provided (--targets FILE|IP,IP,CIDR|hostname)",
              file=sys.stderr)
        return 2

    # Resolve hostname/URL targets (a domain list is the common case) to IPs.
    # Operator-provided names are authorised; their IPs become scope, and we keep
    # name->IP so probes use the domain as Host/SNI and the report attributes it.
    from .resolve import expand_targets
    host_hostnames: dict = {}
    rs = expand_targets(cfg.targets, timeout=cfg.timeout, concurrency=cfg.concurrency)
    if rs.domains:
        print(f" resolving   : {len(rs.domains)} domain(s) → {len(rs.ip_targets)} "
              f"IP(s)" + (f"; {len(rs.unresolved)} unresolved" if rs.unresolved else ""))
        if rs.unresolved:
            shown = ", ".join(rs.unresolved[:8])
            print(f"   unresolved: {shown}"
                  + (f" (+{len(rs.unresolved) - 8} more)" if len(rs.unresolved) > 8 else ""))
    if rs.changed:
        cfg.targets = rs.ip_targets
        host_hostnames = rs.host_map
    if cfg.exclude:                     # resolve hostname exclusions too
        ex = expand_targets(cfg.exclude, timeout=cfg.timeout,
                            concurrency=cfg.concurrency)
        if ex.changed:
            cfg.exclude = ex.ip_targets
    if not cfg.targets:
        print("error: no targets resolved to an IP (all hostnames failed DNS)",
              file=sys.stderr)
        return 2

    print("=" * 60)
    print(" netassess — authorized network attack-surface assessment")
    print("=" * 60)
    print(f" mode        : {cfg.mode}")
    tdesc = ", ".join(cfg.targets[:6]) + (f" (+{len(cfg.targets) - 6} more)"
                                          if len(cfg.targets) > 6 else "")
    print(f" targets     : {tdesc}")
    if cfg.exclude:
        print(f" exclude     : {', '.join(cfg.exclude)}")
    _ports_desc = '1-65535' if cfg.full_port_scan else str(len(cfg.effective_ports())) + ' ports'
    if cfg.skip_portscan:
        _ports_desc += ' (scan SKIPPED — assumed open, probed directly)'
    print(f" ports       : {_ports_desc}")
    print(f" concurrency : {cfg.concurrency}   rate: {cfg.rate}/s   timeout: {cfg.timeout}s")
    cve_status = ("offline+NVD" if cfg.cve_online else "offline KB") if cfg.cve_enabled else "off"
    print(f" cve         : {cve_status}   html: {'yes' if cfg.html_report else 'no'}")
    print(f" report      : min-severity={cfg.report_min_severity}   "
          f"aggregate={'yes' if cfg.report_aggregate else 'no'}")
    if cfg.content_discovery:
        from .adapters.feroxbuster_adapter import FeroxbusterAdapter
        has_ferox = FeroxbusterAdapter().available()
        if cfg.content_tool == "builtin":
            backend = "built-in (GET-only)"
        elif cfg.content_tool == "feroxbuster":
            backend = "feroxbuster" + ("" if has_ferox else " (NOT FOUND -> built-in)")
        else:
            backend = "feroxbuster" if has_ferox else "built-in (feroxbuster not installed)"
        print(f" content     : on via {backend}")
    else:
        print(f" content     : off")
    if cfg.udp_scan:
        print(f" udp         : on ({len(cfg.udp_ports)} ports; SNMP/NTP/DNS probes)")
    else:
        print(f" udp         : off")
    print(f" vhosts      : {'on (TLS SAN/CN vhost probing)' if cfg.vhost_probe else 'off'}")
    if cfg.validate:
        vmode = "credentialed" if cfg.validation_credentialed else "safe/non-destructive"
        print(f" validate    : on ({vmode})")
    else:
        print(f" validate    : off")
    if cfg.nuclei:
        from .adapters.nuclei_adapter import NucleiAdapter
        n_ok = NucleiAdapter().available()
        prof = "thorough" if cfg.nuclei_thorough else "light"
        print(f" nuclei      : on ({prof} profile, rate {cfg.nuclei_rate}/s)"
              + ("" if n_ok else " — NOT INSTALLED, will skip"))
    else:
        print(f" nuclei      : off")
    print("-" * 60)

    engine = AssessmentEngine(cfg, log=_logger(True), host_hostnames=host_hostnames)
    engine.run()
    paths = engine.report()
    print("-" * 60)
    print(f" state  : {os.path.join(cfg.output_dir, cfg.state_file)}")
    print(f" report : {paths['markdown']}")
    print(f" json   : {paths['json']}")
    if paths.get("html"):
        print(f" html   : {paths['html']}")
    print("=" * 60)
    return 0


def cmd_scope_check(args) -> int:
    cfg = _build_config(args)
    scope = ScopeEngine(cfg)
    summ = scope.summary()
    print("Scope check")
    print("-----------")
    print(f"Authorized networks : {summ['included_networks']}")
    print(f"Excluded networks   : {summ['excluded_networks']}")
    print(f"Forbidden ports     : {summ['forbidden_ports']}")
    if summ["parse_errors"]:
        print(f"Parse errors        : {summ['parse_errors']}")
    hosts = scope.expand_hosts()
    print(f"In-scope hosts      : {len(hosts)}")
    for ip in hosts[:20]:
        print(f"  - {ip}")
    if len(hosts) > 20:
        print(f"  … and {len(hosts) - 20} more")
    # demonstrate the gate on a couple of targets
    if getattr(args, "test", None):
        for t in args.test.split(","):
            t = t.strip()
            d = scope.authorize(t)
            print(f"authorize({t}) -> {d.verdict.value}: {d.reason}")
    return 0


def cmd_diff(args) -> int:
    from .diff import diff_graphs, render_markdown, write_diff

    for label, path in (("--old", args.old), ("--new", args.new)):
        if not os.path.isfile(path):
            print(f"error: {label} state file not found: {path}", file=sys.stderr)
            return 2
    old = AssetGraph.load(args.old)
    new = AssetGraph.load(args.new)
    d = diff_graphs(old, new, old_label=args.old, new_label=args.new)

    # always print the markdown to stdout for quick inspection
    print(render_markdown(d))

    if args.output:
        paths = write_diff(d, args.output)
        print(f"diff written: {paths['markdown']}  |  {paths['json']}")

    # exit code 1 signals "changes detected" for CI/monitoring pipelines,
    # unless the user only cares about failures via --fail-on.
    if args.fail_on == "any" and not d.is_empty():
        return 1
    if args.fail_on == "worse" and (d.ports_opened or d.findings_new):
        return 1
    return 0


def cmd_cve_sync(args) -> int:
    from .cve.nvd_sync import NVDSync, PRODUCTS, default_cache_path

    products = PRODUCTS
    if getattr(args, "products", None):
        wanted = {p.strip().lower() for p in args.products.split(",")}
        products = [p for p in PRODUCTS
                    if p["name"].lower() in wanted
                    or any(k in wanted for k in p["keywords"])]
        if not products:
            print(f"error: no known products match {sorted(wanted)}; known: "
                  f"{', '.join(p['name'] for p in PRODUCTS)}", file=sys.stderr)
            return 2
    out = args.output or default_cache_path()
    print("Syncing offline CVE data from NVD (talks to NVD, not your targets).")
    print("Tip: set NVD_API_KEY for a much higher rate limit.\n")
    res = NVDSync().sync(products=products, out_path=out)
    print(f"\nDone: {res['count']} CVE(s) cached at {res['path']}")
    print("Future scans use this automatically (offline, no target traffic).")
    return 0


def cmd_kev_sync(args) -> int:
    from .cve.kev import KEVSync, default_cache_path
    out = args.output or default_cache_path()
    print("Syncing CISA KEV + FIRST EPSS (talks to CISA/FIRST, not your targets).")
    res = KEVSync().sync(out_path=out)
    print(f"\nDone: {res['kev']} KEV CVE(s), {res['epss']} EPSS score(s) at {res['path']}")
    print("Future scans flag actively-exploited CVEs automatically (offline).")
    return 0 if (res["kev"] or res["epss"]) else 1


def cmd_report(args) -> int:
    state_path = args.state
    if not os.path.isfile(state_path):
        print(f"error: state file not found: {state_path}", file=sys.stderr)
        return 2
    graph = AssetGraph.load(state_path)
    cfg = Config(targets=graph.meta.get("targets", []),
                 output_dir=args.output or os.path.dirname(state_path) or ".")
    scope = ScopeEngine(cfg)
    rg = ReportGenerator(graph, scope, cfg)
    paths = rg.write(cfg.output_dir)
    print(f"report : {paths['markdown']}")
    print(f"json   : {paths['json']}")
    return 0


# --------------------------------------------------------------------------- #
# parser
# --------------------------------------------------------------------------- #
def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        prog="netassess",
        description="Authorized, safe network attack-surface assessment platform.")
    sub = p.add_subparsers(dest="group", required=True)

    # network scan
    net = sub.add_parser("network", help="network assessment commands")
    netsub = net.add_subparsers(dest="cmd", required=True)
    scan = netsub.add_parser("scan", help="run a full assessment")
    _add_scan_args(scan)
    scan.set_defaults(func=cmd_scan)

    # top-level `scan` alias
    scan2 = sub.add_parser("scan", help="alias for `network scan`")
    _add_scan_args(scan2)
    scan2.set_defaults(func=cmd_scan)

    # scope
    scope = sub.add_parser("scope", help="scope engine utilities")
    scopesub = scope.add_subparsers(dest="cmd", required=True)
    chk = scopesub.add_parser("check", help="validate/expand scope, test the gate")
    chk.add_argument("--targets", required=True)
    chk.add_argument("--exclude")
    chk.add_argument("--test", help="comma IPs to run through authorize()")
    chk.set_defaults(func=cmd_scope_check)

    # diff
    dp = sub.add_parser("diff", help="compare two state.json runs")
    dp.add_argument("--old", required=True, help="baseline state.json")
    dp.add_argument("--new", required=True, help="current state.json")
    dp.add_argument("--output", help="directory to write diff.md / diff.json")
    dp.add_argument("--fail-on", dest="fail_on", choices=["never", "any", "worse"],
                    default="never",
                    help="exit non-zero on: any change, or 'worse' (new open "
                         "ports/findings). Default never.")
    dp.set_defaults(func=cmd_diff)

    # cve sync
    cve = sub.add_parser("cve", help="CVE data utilities")
    cvesub = cve.add_subparsers(dest="cmd", required=True)
    sync = cvesub.add_parser("sync", help="download offline NVD CVE cache "
                                          "(no target traffic)")
    sync.add_argument("--output", help="cache path (default ~/.netassess/nvd.json)")
    sync.add_argument("--products", help="comma list to limit (e.g. nginx,openssh); "
                                         "default = all fingerprinted products")
    sync.set_defaults(func=cmd_cve_sync)

    # kev sync
    kev = sub.add_parser("kev", help="exploitation-intel (CISA KEV + EPSS) utilities")
    kevsub = kev.add_subparsers(dest="cmd", required=True)
    ksync = kevsub.add_parser("sync", help="download CISA KEV + EPSS cache "
                                           "(no target traffic)")
    ksync.add_argument("--output", help="cache path (default ~/.netassess/kev.json)")
    ksync.set_defaults(func=cmd_kev_sync)

    # report
    rep = sub.add_parser("report", help="regenerate a report from saved state")
    rep.add_argument("--state", required=True, help="path to state.json")
    rep.add_argument("--output")
    rep.set_defaults(func=cmd_report)
    return p


def _add_scan_args(sp: argparse.ArgumentParser):
    sp.add_argument("--targets", required=True,
                    help="file path, or comma-separated IPs/CIDRs")
    sp.add_argument("--exclude", help="file/comma IPs/CIDRs to exclude")
    sp.add_argument("--mode", choices=["deterministic", "ai", "auto"],
                    default="deterministic")
    sp.add_argument("--ports", help="explicit set, e.g. 22,80,443 or 1-1024 "
                                    "(overrides the default top-1000)")
    sp.add_argument("--common-ports", dest="common_ports", action="store_true",
                    help="fast preset: 40 high-signal ports instead of top-1000")
    sp.add_argument("--full-port-scan", action="store_true", dest="full_port_scan",
                    help="scan all 65535 TCP ports")
    sp.add_argument("--no-smtp-relay-test", dest="no_smtp_relay_test",
                    action="store_true",
                    help="disable the SMTP open-relay test (it runs by default; "
                         "non-destructive — aborts before DATA, no mail is sent)")
    sp.add_argument("--udp", action="store_true",
                    help="also scan common UDP ports (DNS/SNMP/NTP/NetBIOS/…) "
                         "with protocol-aware probes")
    sp.add_argument("--udp-ports", dest="udp_ports",
                    help="UDP ports to scan, e.g. 53,123,161 (default: common set)")
    sp.add_argument("--no-vhosts", dest="no_vhosts", action="store_true",
                    help="disable virtual-host discovery (it runs by default: probes "
                         "TLS SAN/CN hostnames via SNI+Host on the same in-scope IP)")
    sp.add_argument("--no-progress", dest="no_progress", action="store_true",
                    help="suppress the staged plan + live progress output")
    sp.add_argument("--no-validate", dest="no_validate", action="store_true",
                    help="disable the validation layer (it runs by default: safe, "
                         "non-destructive assessment of candidate findings)")
    sp.add_argument("--auth-config", dest="auth_config",
                    help="JSON file of per-host key-based SSH creds for OPT-IN "
                         "credentialed validation, e.g. "
                         '{"1.2.3.4":{"user":"audit","key":"~/.ssh/id","port":22}}; '
                         "read-only commands only, passwords never used")
    sp.add_argument("--nuclei", action="store_true",
                    help="run nuclei (if installed) against discovered URLs with a "
                         "light, target-friendly template profile")
    sp.add_argument("--nuclei-thorough", dest="nuclei_thorough",
                    action="store_true",
                    help="run nuclei with a broader template set (still excludes "
                         "dos/fuzzing/intrusive/headless)")
    sp.add_argument("--nuclei-rate", dest="nuclei_rate", type=int,
                    help="nuclei requests/sec cap (default 30)")
    sp.add_argument("--deep", action="store_true", help="deeper (still safe) probes")
    sp.add_argument("--concurrency", type=int)
    sp.add_argument("--rate", type=float, help="max new connections/sec")
    sp.add_argument("--timeout", type=float, help="per-connection timeout ceiling (s)")
    sp.add_argument("--retries", type=int)
    sp.add_argument("--no-adaptive-timeout", dest="no_adaptive_timeout",
                    action="store_true",
                    help="disable RTT-based per-host timeouts; use the full "
                         "--timeout for every connection")
    sp.add_argument("--discovery", choices=["auto", "nmap", "tcp"],
                    help="host discovery: auto (nmap -sn if available + TCP "
                         "fallback), nmap (nmap -sn only), or tcp (built-in "
                         "TCP-connect). Default auto.")
    sp.add_argument("--skip-discovery", dest="skip_discovery", action="store_true",
                    help="skip discovery; treat every in-scope host as live")
    sp.add_argument("--skip-portscan", dest="skip_portscan", action="store_true",
                    help="skip the port scan; assume --ports are open and probe "
                         "them directly (best with a small --ports set, e.g. "
                         "80,443,8080,8443). Probes fail gracefully on closed ports")
    sp.add_argument("--output", help="output directory")
    sp.add_argument("--ai-provider", dest="ai_provider",
                    choices=["none", "anthropic"], default="none")
    sp.add_argument("--content-discovery", dest="content_discovery",
                    action="store_true",
                    help="enumerate common web paths (admin/login/api/.env etc.) "
                         "on discovered HTTP services — GET-only, scope-gated")
    sp.add_argument("--wordlist", dest="wordlist",
                    help="file of extra paths (one per line) to append to the "
                         "built-in content-discovery list")
    sp.add_argument("--content-quick", dest="content_quick", action="store_true",
                    help="content discovery uses only the small curated list "
                         "(~70 paths) instead of the bundled SecLists common.txt")
    sp.add_argument("--content-tool", dest="content_tool",
                    choices=["auto", "feroxbuster", "builtin"], default="auto",
                    help="content-discovery engine: auto (feroxbuster if "
                         "installed, else built-in), or force one")
    sp.add_argument("--content-depth", dest="content_depth", type=int,
                    help="feroxbuster recursion depth (default 2)")
    sp.add_argument("--content-extensions", dest="content_extensions",
                    help="feroxbuster extensions to append, e.g. php,bak,zip,sql")
    sp.add_argument("--content-thorough", dest="content_thorough",
                    action="store_true",
                    help="feroxbuster: also collect real extensions and probe "
                         "for backups of discovered pages")
    sp.add_argument("--no-cve", dest="no_cve", action="store_true",
                    help="disable CVE correlation")
    sp.add_argument("--cve-online", dest="cve_online", action="store_true",
                    help="enrich CVE findings via NVD (network, opt-in)")
    sp.add_argument("--cve-db", dest="cve_db",
                    help="path to an extra CVE JSON file to merge into the KB")
    sp.add_argument("--no-html", dest="no_html", action="store_true",
                    help="do not emit report.html")
    sp.add_argument("--min-severity", dest="min_severity",
                    choices=["info", "low", "medium", "high", "critical"],
                    help="lowest severity shown in reports (default: medium; "
                         "low/info are suppressed as noise)")
    sp.add_argument("--all-findings", dest="all_findings", action="store_true",
                    help="include every finding in reports (same as "
                         "--min-severity info)")
    sp.add_argument("--no-aggregate", dest="no_aggregate", action="store_true",
                    help="list findings per host instead of grouping the same "
                         "issue across hosts")
    sp.add_argument("--include-noise", dest="include_noise", action="store_true",
                    help="also report low-signal findings that are hidden by "
                         "default (missing security headers, version disclosure)")


def _clean_exit(code: int) -> int:
    """Hand the terminal back to the shell deterministically.

    All work (state.json + reports) is flushed to disk synchronously before we
    get here. If a shelled-out tool (nmap/nuclei/feroxbuster) left a background
    child, or a library left a non-daemon thread, the Python interpreter would
    otherwise block at shutdown waiting on it and the prompt would never return.
    When we detect such a lingering non-daemon thread, exit immediately rather
    than hang. In the normal case (nothing lingering) we return as usual so
    atexit handlers still run.
    """
    try:
        sys.stdout.flush()
        sys.stderr.flush()
    except Exception:
        pass
    import threading
    lingering = [t for t in threading.enumerate()
                 if t is not threading.main_thread() and t.is_alive()
                 and not t.daemon]
    if lingering:
        if os.environ.get("NETASSESS_DEBUG_EXIT"):
            names = ", ".join(sorted(t.name for t in lingering))
            print(f"[exit] {len(lingering)} lingering non-daemon thread(s) would "
                  f"block shutdown; exiting now: {names}", file=sys.stderr)
        os._exit(code if isinstance(code, int) else 0)
    return code


def main(argv=None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)
    try:
        code = args.func(args)
    except FileNotFoundError as exc:
        print(f"error: {exc}", file=sys.stderr)
        code = 2
    except KeyboardInterrupt:
        print("\ninterrupted", file=sys.stderr)
        code = 130
    return _clean_exit(code if isinstance(code, int) else 0)

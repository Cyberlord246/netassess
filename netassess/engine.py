"""Assessment engine — the pipeline conductor.

Runs the full flow:
    scope -> discovery -> reverse DNS -> port scan -> service ID ->
    protocol probes -> HTTP/TLS analysis -> tech detection ->
    vuln assessment -> correlation -> prioritization -> report

Everything routes through the Scope Engine and the persistent AssetGraph. The
Orchestrator chooses task ordering (deterministic or AI-assisted) but every
task is scope-checked again at execution time.
"""
from __future__ import annotations

import os
import sys
from concurrent.futures import ThreadPoolExecutor, as_completed

from .adapters.nmap_adapter import NmapAdapter
from .ai.orchestrator import Orchestrator, TaskType
from .config import Config
from .content_discovery import ContentDiscovery, _BUNDLED_WORDLIST
from .cve import CVEEngine
from .discovery import DiscoveryEngine
from .dns_recon import ReverseDNS
from .models import HostStatus
from .ports import PortScanner, effective_timeout
from .roles import classify, detect_anomalies
from .probers import build_generic, build_probes
from .report import ReportGenerator
from .scope import ScopeEngine
from .services import identify
from .state import AssetGraph
from .udp import UDPScanner
from .vhost import VhostProber
from .vuln import VulnAssessmentEngine


class AssessmentEngine:
    def __init__(self, config: Config, log=None):
        self.config = config
        self.scope = ScopeEngine(config)
        self.graph = AssetGraph()
        self.graph.meta = {"mode": config.mode, "targets": config.targets}
        self.nmap = NmapAdapter()
        self.scanner = PortScanner(config, self.scope, self.nmap)
        self.discovery = DiscoveryEngine(config, self.scope)
        self.rdns = ReverseDNS(timeout=config.timeout)
        self.probes = build_probes(config, self.scope)
        self.generic = build_generic(config, self.scope)
        self.vuln = VulnAssessmentEngine(config)
        self.cve = self._build_cve_engine(config)
        self.content = ContentDiscovery(config, self.scope) if config.content_discovery else None
        self.ferox = self._build_ferox(config)
        self.udp = UDPScanner(config, self.scope) if config.udp_scan else None
        self.vhost = VhostProber(config, self.scope) if config.vhost_probe else None
        self.nuclei = self._build_nuclei(config)
        self.orch = Orchestrator(config)
        self._log = log or (lambda *a, **k: None)

    def _build_nuclei(self, config: Config):
        if not config.nuclei:
            return None
        from .adapters.nuclei_adapter import NucleiAdapter
        return NucleiAdapter()

    def _build_ferox(self, config: Config):
        if not config.content_discovery or config.content_tool == "builtin":
            return None
        from .adapters.feroxbuster_adapter import FeroxbusterAdapter
        adapter = FeroxbusterAdapter()
        if config.content_tool == "feroxbuster":
            return adapter          # explicit request; used even if we must warn
        return adapter if adapter.available() else None  # auto

    def _build_cve_engine(self, config: Config):
        if not config.cve_enabled:
            return None
        online = None
        if config.cve_online:
            from .cve.online import NVDOnlineAdapter
            online = NVDOnlineAdapter()
        return CVEEngine(config, online_adapter=online)

    # -- public ----------------------------------------------------------- #
    def run(self) -> AssetGraph:
        self._log(f"[scope] backend={self.scanner.backend} "
                  f"nmap={'yes' if self.nmap.available() else 'no'}")
        if self.scope.parse_errors:
            for e in self.scope.parse_errors:
                self._log(f"[scope] parse warning: {e}")
        if not self.scope.include:
            self._log("[scope] no valid authorized targets — nothing to do.")
            return self.graph

        hosts = self.scope.expand_hosts()
        self._log(f"[scope] {len(hosts)} in-scope host(s) authorized")

        self._phase_discovery(hosts)
        self._save()
        self._phase_rdns()
        self._save()
        self._phase_portscan()
        self._save()
        self._phase_service_id()
        self._phase_probe()
        self._save()
        self._phase_content()
        self._save()
        self._phase_vhost()
        self._save()
        self._phase_nuclei()
        self._save()
        self._phase_udp()
        self._save()
        self._phase_roles()
        self._save()
        self._phase_vuln()
        self._save()
        self._phase_cve()
        self._save()
        return self.graph

    # -- phases ----------------------------------------------------------- #
    def _phase_discovery(self, ips: list[str]):
        if self.config.skip_discovery:
            for ip in ips:
                h = self.graph.get_or_create(ip)
                h.status = HostStatus.LIVE
                h.discovery_method = "assumed (discovery skipped)"
            self._log(f"[discovery] skipped — treating {len(ips)} host(s) as live")
            return
        mode = self.config.discovery_mode
        use_nmap = (mode in ("auto", "nmap")) and self.nmap.available()
        if mode == "nmap" and not self.nmap.available():
            self._log("[discovery] nmap requested but not found — using TCP discovery")

        remaining = ips
        if use_nmap:
            self._log(f"[discovery] nmap -sn host discovery on {len(ips)} host(s)…")
            up, res = self.nmap.discover(ips)
            if res.not_found:
                self._log("[discovery] nmap unavailable — falling back to TCP")
            else:
                for ip in up:
                    h = self.graph.get_or_create(ip)
                    h.status = HostStatus.LIVE
                    h.discovery_method = "nmap -sn"
                self._log(f"[discovery] nmap reports {len(up)} host(s) up")
                # 'nmap' mode = nmap only; 'auto' = TCP-probe the ones nmap
                # didn't confirm, so filtered-but-TCP-reachable hosts aren't lost
                remaining = [] if mode == "nmap" else [ip for ip in ips if ip not in up]

        if remaining:
            self._log(f"[discovery] TCP-probing {len(remaining)} host(s)…")
            results = self.discovery.discover(remaining,
                                              progress=self._progress("discovery"))
            for host in results:
                existing = self.graph.get_or_create(host.ip)
                existing.status = host.status
                existing.discovery_method = host.discovery_method
                existing.latency_ms = host.latency_ms
                existing.notes.extend(host.notes)

        live = len(self.graph.live_hosts())
        self._log(f"\n[discovery] {live} live host(s)")

    def _phase_rdns(self):
        targets = [h.ip for h in self.graph.hosts.values()
                   if h.status in (HostStatus.LIVE, HostStatus.FILTERED)]
        if not targets:
            return
        self._log(f"[rdns] resolving {len(targets)} host(s)…")
        recs = self.rdns.lookup_many(targets, concurrency=self.config.concurrency)
        for ip, rec in recs.items():
            if rec["hostnames"]:
                self.graph.get_or_create(ip).hostnames = rec["hostnames"]

    def _phase_portscan(self):
        targets = [h.ip for h in self.graph.hosts.values()
                   if h.status in (HostStatus.LIVE, HostStatus.FILTERED)]
        if not targets:
            self._log("[ports] no live hosts to scan")
            return
        ports = self.config.effective_ports()
        # per-host adaptive timeout from discovery RTT (fast hosts wait less)
        host_timeouts = {
            ip: effective_timeout(self.graph.get_or_create(ip).latency_ms, self.config)
            for ip in targets
        }
        if self.config.adaptive_timeout:
            sample = [t for t in host_timeouts.values()]
            tightened = sum(1 for t in sample if t < self.config.timeout)
            self._log(f"[ports] adaptive timeout active — {tightened}/{len(sample)} "
                      f"host(s) using a tighter-than-{self.config.timeout}s timeout")
        self._log(f"[ports] scanning {len(targets)} host(s) × {len(ports)} port(s) "
                  f"via {self.scanner.backend} (concurrent)…")
        results = self.scanner.scan_hosts(targets, ports,
                                          progress=self._progress("ports"),
                                          host_timeouts=host_timeouts)
        opened = 0
        for ip, found in results.items():
            host = self.graph.get_or_create(ip)
            for p in found:
                host.ports[p.number] = p
            if found:
                opened += 1
                self._log(f"\n[ports] {ip}: {len(found)} open "
                          f"({', '.join(str(p.number) for p in found)})")
        if not opened:
            self._log("\n[ports] no open ports found")

    def _phase_service_id(self):
        for _h, port in self.graph.iter_open_ports():
            identify(port)

    def _phase_probe(self):
        tasks = self.orch.plan_probes(self.graph, self.probes)
        if not tasks:
            self._log("[probe] no probe targets")
            return
        self._log(f"[probe] running {len(tasks)} probe task(s) "
                  f"(mode={self.config.mode})…")

        def run_task(task):
            host = self.graph.get(task.target)
            if host is None or task.port not in host.ports:
                return
            port = host.ports[task.port]
            ran_any = False
            for probe in self.probes:
                if not probe.matches(port):
                    continue
                ran_any = True
                self._run_probe_safe(probe, host, port)
            if not ran_any:
                self._run_probe_safe(self.generic, host, port)

        with ThreadPoolExecutor(max_workers=max(2, self.config.concurrency // 4)) as pool:
            futures = [pool.submit(run_task, t) for t in tasks]
            for _ in as_completed(futures):
                pass
        self._log(f"[probe] complete — {len(self.graph.all_http_services())} "
                  "HTTP service(s) analysed")

    def _run_probe_safe(self, probe, host, port):
        """Error-handling wrapper: capture, classify, never crash the pipeline."""
        try:
            result = probe.probe(host, port)
        except Exception as exc:  # defensive: a probe bug must not kill the run
            host.notes.append(f"probe {probe.name} error on {port.number}: {exc}")
            return
        if result.error:
            return
        for f in result.findings:
            host.add_finding(f)

    def _phase_content(self):
        if self.content is None:
            return
        services = self.graph.all_http_services()
        if not services:
            self._log("[content] no HTTP services to enumerate")
            return

        use_ferox = self.ferox is not None and self.ferox.available()
        if self.ferox is not None and not use_ferox:
            self._log("[content] feroxbuster requested but not found on PATH — "
                      "falling back to built-in probe")

        backend = "feroxbuster" if use_ferox else "built-in"
        self._log(f"[content] enumerating web content on {len(services)} "
                  f"service(s) via {backend}…")

        added = 0
        for host, svc in services:
            # Mandatory scope gate before handing a target to any tool.
            if not self.scope.authorize(host.ip, svc.port).allowed:
                continue
            try:
                if use_ferox:
                    findings = self._run_ferox(host, svc)
                else:
                    findings = self.content.scan_service(host, svc)
            except Exception as exc:
                host.notes.append(f"content discovery error on {svc.port}: {exc}")
                continue
            for f in findings:
                before = len(host.findings)
                host.add_finding(f)
                if len(host.findings) > before:
                    added += 1
        self._log(f"[content] {added} path finding(s) added")

    def _run_ferox(self, host, svc):
        wordlist = self.config.content_wordlist or _BUNDLED_WORDLIST
        _recs, findings, res = self.ferox.scan_service(
            host, svc, wordlist=wordlist,
            threads=self.config.concurrency, depth=self.config.content_depth,
            timeout=int(self.config.timeout) + 5, rate=self.config.rate,
            extensions=self.config.content_extensions,
            thorough=self.config.content_thorough,
        )
        if res.not_found:
            # shouldn't happen (we checked available()), but be safe
            return self.content.scan_service(host, svc)
        return findings

    def _phase_vhost(self):
        if self.vhost is None:
            return
        # snapshot services first: probing appends new vhost entries
        services = list(self.graph.all_http_services())
        # only TLS services carry SANs worth probing
        services = [(h, s) for h, s in services if s.scheme == "https" or s.tls]
        if not services:
            self._log("[vhost] no TLS web services to derive SANs from")
            return
        self._log(f"[vhost] probing TLS SAN/CN hostnames across "
                  f"{len(services)} service(s)…")
        added = 0
        for host, svc in services:
            try:
                for f in self.vhost.probe_service(host, svc):
                    before = len(host.findings)
                    host.add_finding(f)
                    if len(host.findings) > before:
                        added += 1
            except Exception as exc:
                host.notes.append(f"vhost probe error on {svc.port}: {exc}")
        self._log(f"[vhost] {added} distinct virtual host(s) discovered")

    def _phase_nuclei(self):
        if self.nuclei is None:
            return
        if not self.nuclei.available():
            self._log("[nuclei] requested but nuclei not found on PATH — skipped")
            return
        # only in-scope, already-discovered web URLs
        urls = []
        for host, svc in self.graph.all_http_services():
            if self.scope.authorize(svc.ip, svc.port).allowed:
                urls.append(svc.url)
        urls = sorted(set(urls))
        if not urls:
            self._log("[nuclei] no discovered web URLs to test")
            return
        profile = "thorough" if self.config.nuclei_thorough else "light"
        self._log(f"[nuclei] scanning {len(urls)} URL(s) ({profile} profile, "
                  f"rate {self.config.nuclei_rate}/s)…")
        findings, res = self.nuclei.scan(
            urls, thorough=self.config.nuclei_thorough, rate=self.config.nuclei_rate)
        if res.not_found:
            self._log("[nuclei] binary vanished — skipped")
            return
        added = 0
        for f in findings:
            ip = f.asset.split(":", 1)[0]
            host = self.graph.get(ip) or self.graph.get_or_create(ip)
            before = len(host.findings)
            host.add_finding(f)
            if len(host.findings) > before:
                added += 1
        self._log(f"[nuclei] {added} finding(s) added")

    def _phase_udp(self):
        if self.udp is None:
            return
        targets = [h.ip for h in self.graph.hosts.values()
                   if h.status in (HostStatus.LIVE, HostStatus.FILTERED)]
        if not targets:
            return
        ports = self.config.udp_ports
        self._log(f"[udp] scanning {len(ports)} UDP port(s) on {len(targets)} host(s)…")
        open_count = 0
        findings = 0
        for ip in targets:
            results = self.udp.scan_host(ip, ports)
            host = self.graph.get_or_create(ip)
            for p in results:
                host.udp_ports[p.number] = p
                if p.state.value == "open":
                    open_count += 1
                for f in self.udp.analyze(ip, p):
                    before = len(host.findings)
                    host.add_finding(f)
                    if len(host.findings) > before:
                        findings += 1
        self._log(f"[udp] {open_count} open UDP port(s), {findings} finding(s) added")

    def _phase_roles(self):
        # pure analysis over the graph — no network
        self._log("[roles] classifying host roles and detecting anomalies…")
        classified = 0
        anomalies = 0
        for host in self.graph.hosts.values():
            if not host.open_ports() and not host.udp_ports:
                continue
            rr = classify(host)
            host.primary_role = rr.primary
            host.roles = rr.roles
            classified += 1
            for f in detect_anomalies(host, rr):
                before = len(host.findings)
                host.add_finding(f)
                if len(host.findings) > before:
                    anomalies += 1
        self._log(f"[roles] classified {classified} host(s); {anomalies} "
                  "role anomaly finding(s)")

    def _phase_vuln(self):
        self._log("[vuln] running safe vulnerability heuristics…")
        n = self.vuln.assess(self.graph)
        self._log(f"[vuln] {n} finding(s) added")

    def _phase_cve(self):
        if self.cve is None:
            self._log("[cve] disabled")
            return
        mode = "offline+NVD" if self.config.cve_online else "offline KB"
        cache_note = (f", +{self.cve.nvd_cache_loaded} from NVD cache"
                      if getattr(self.cve, "nvd_cache_loaded", 0) else
                      " (no NVD cache — run `netassess cve sync`)")
        self._log(f"[cve] correlating service versions against "
                  f"{len(self.cve.db)} CVE(s) [{mode}{cache_note}]…")
        n = self.cve.assess(self.graph)
        self._log(f"[cve] {n} CVE lead(s) added (marked NEEDS_VALIDATION)")
        self._enrich_kev()

    def _enrich_kev(self):
        from .cve.kev import KEVData, default_cache_path, enrich_graph
        import os as _os
        cache = self.config.kev_cache or default_cache_path()
        if not _os.path.isfile(cache):
            self._log("[kev] no KEV/EPSS cache — run `netassess kev sync` to flag "
                      "actively-exploited CVEs")
            return
        data = KEVData.load(cache)
        if not data.available:
            return
        counts = enrich_graph(self.graph, data)
        self._log(f"[kev] {counts['kev']} finding(s) flagged actively-exploited "
                  f"(CISA KEV), {counts['epss']} scored with EPSS")

    # -- report ----------------------------------------------------------- #
    def report(self) -> dict:
        rg = ReportGenerator(self.graph, self.scope, self.config)
        paths = rg.write(self.config.output_dir)
        return paths

    # -- helpers ---------------------------------------------------------- #
    def _save(self):
        path = os.path.join(self.config.output_dir, self.config.state_file)
        try:
            self.graph.save(path)
        except OSError as exc:
            self._log(f"[state] save failed: {exc}")

    def _progress(self, label):
        def cb(done, total):
            pct = int(done * 100 / total) if total else 100
            sys.stdout.write(f"\r[{label}] {done}/{total} ({pct}%)")
            sys.stdout.flush()
        return cb

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
from .models import HostStatus, Port, PortState, Service
from .ports import PortScanner, effective_timeout
from .progress import Progress
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
    def __init__(self, config: Config, log=None, host_hostnames=None):
        self.config = config
        # {ip: [hostnames]} for user-provided domains that resolved to these IPs
        self._provided_hostnames = host_hostnames or {}
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
        self.httpx = self._build_httpx(config)
        self.udp = UDPScanner(config, self.scope) if config.udp_scan else None
        self.vhost = VhostProber(config, self.scope) if config.vhost_probe else None
        self.nuclei = self._build_nuclei(config)
        self.orch = Orchestrator(config)
        self._log = log or (lambda *a, **k: None)
        self.progress = Progress(enabled=getattr(config, "show_progress", True))

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

    def _build_httpx(self, config: Config):
        if getattr(config, "http_tool", "auto") == "builtin":
            return None
        from .adapters.httpx_adapter import HttpxAdapter
        adapter = HttpxAdapter()
        if config.http_tool == "httpx":
            return adapter          # explicit request; used even if we must warn
        return adapter if adapter.available() else None   # auto

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

        # seed operator-provided domain names onto their resolved IPs, so the HTTP
        # probe uses them as Host/SNI, the vhost prober probes them, and findings
        # are attributed back to the domain in the inventory
        if self._provided_hostnames:
            seeded = 0
            for ip, names in self._provided_hostnames.items():
                h = self.graph.get_or_create(ip)
                for n in names:
                    if n not in h.hostnames:
                        h.hostnames.append(n)
                        seeded += 1
            self._log(f"[scope] seeded {seeded} provided hostname(s) across "
                      f"{len(self._provided_hostnames)} resolved IP(s)")

        # Ordered plan. Only enabled stages are listed/run, so the [k/N] counts
        # and the plan the operator sees reflect what will actually happen.
        stages = [
            ("Host discovery",             lambda: self._phase_discovery(hosts), True,  self._sum_discovery),
            ("Reverse DNS",                self._phase_rdns,        getattr(self.config, "reverse_dns", True), self._sum_rdns),
            ("Port scan",                  self._phase_portscan,    True,                self._sum_ports),
            ("Service identification",     self._phase_service_id,  True,                self._sum_services),
            ("Service & protocol probes",  self._phase_probe,       True,                self._sum_http),
            ("Virtual-host discovery",     self._phase_vhost,       self.vhost is not None,   self._sum_vhost),
            ("Web content discovery",      self._phase_content,     self.content is not None, self._sum_content),
            ("Nuclei templates",           self._phase_nuclei,      self.nuclei is not None,  None),
            ("UDP scan",                   self._phase_udp,         self.udp is not None,     self._sum_udp),
            ("Domain collection",          self._phase_domains,     True,                self._sum_domains),
            ("Vulnerability heuristics",   self._phase_vuln,        True,                None),
            ("CVE correlation",            self._phase_cve,         self.cve is not None, self._sum_cve),
            ("Validation & assessment",    self._phase_validate,    getattr(self.config, "validate", True), None),
            ("Role & anomaly analysis",    self._phase_roles,       True,                self._sum_roles),
        ]
        active = [(label, fn, summ) for label, fn, enabled, summ in stages if enabled]
        self.progress.set_plan([label for label, _, _ in active])

        for i, (label, fn, summ) in enumerate(active, 1):
            self.progress.reset_counter()
            self.progress.stage_start(i, label)
            fn()
            summary = ""
            if summ is not None:
                try:
                    summary = summ()
                except Exception:
                    summary = ""
            self.progress.stage_done(i, label, summary)
            self._save()
        return self.graph

    # -- stage summaries (short, shown on the DONE line) ------------------ #
    def _sum_discovery(self) -> str:
        return f"{len(self.graph.live_hosts())} live host(s)"

    def _sum_rdns(self) -> str:
        n = sum(1 for h in self.graph.hosts.values() if h.hostnames)
        return f"{n} host(s) with a name"

    def _sum_ports(self) -> str:
        n = sum(len(h.open_ports()) for h in self.graph.hosts.values())
        hosts = sum(1 for h in self.graph.hosts.values() if h.open_ports())
        return f"{n} open port(s) across {hosts} host(s)"

    def _sum_services(self) -> str:
        n = sum(len(h.open_ports()) for h in self.graph.hosts.values())
        return f"{n} service(s) identified"

    def _sum_http(self) -> str:
        return f"{len(self.graph.all_http_services())} web service(s)"

    def _sum_content(self) -> str:
        n = sum(len(s.discovered_paths) for _h, s in self.graph.all_http_services())
        return f"{n} path(s) discovered"

    def _sum_vhost(self) -> str:
        total = sum(len(h.domains) for h in self.graph.hosts.values())
        return f"{total} hostname(s) known"

    def _sum_udp(self) -> str:
        n = sum(1 for h in self.graph.hosts.values()
                for p in h.udp_ports.values() if p.state.value == "open")
        return f"{n} open UDP port(s)"

    def _sum_domains(self) -> str:
        total = sum(len(h.domains) for h in self.graph.hosts.values())
        return f"{total} hostname(s)"

    def _sum_cve(self) -> str:
        n = sum(1 for _h, f in self.graph.all_findings()
                if f.category == "known-vulnerability")
        return f"{n} CVE lead(s)"

    def _sum_roles(self) -> str:
        n = sum(1 for h in self.graph.hosts.values() if h.primary_role)
        return f"{n} host(s) classified"

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
                # merge PTR names with any operator-provided domains (keep the
                # provided ones first; they drive Host/SNI selection)
                names = self.graph.get_or_create(ip).hostnames
                for hn in rec["hostnames"]:
                    if hn not in names:
                        names.append(hn)

    def _phase_portscan(self):
        targets = [h.ip for h in self.graph.hosts.values()
                   if h.status in (HostStatus.LIVE, HostStatus.FILTERED)]
        if not targets:
            self._log("[ports] no live hosts to scan")
            return
        ports = self.config.effective_ports()

        # Skip the scan entirely: assume the configured ports are open and let the
        # service-ID + probe stages confirm which actually respond (probes fail
        # gracefully on closed ports). Best paired with a small --ports set.
        if self.config.skip_portscan:
            for ip in targets:
                host = self.graph.get_or_create(ip)
                for num in ports:
                    if num not in host.ports:
                        host.ports[num] = Port(number=num, state=PortState.OPEN,
                                               service=Service())
            self._log(f"[ports] scan SKIPPED — assuming {len(ports)} configured "
                      f"port(s) open on {len(targets)} host(s); probes will confirm "
                      "which respond")
            if len(ports) > 50:
                self._log(f"[ports] NOTE: {len(ports)} ports/host will be probed "
                          "directly — pair --skip-portscan with a small --ports set "
                          "(e.g. 80,443,8080,8443) to keep this fast")
            return

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

        # Fast bulk HTTP fingerprint via httpx (if active): identifies + fingerprints
        # all candidate web endpoints in one async pass, far faster than the built-in
        # per-service GET. When it runs, the built-in HTTPProbe is dropped from the
        # loop (httpx did the fetch); misconfig checks still run on confirmed services.
        httpx_web = self._run_httpx_bulk() if self._httpx_active() else None
        probes = self.probes
        if httpx_web is not None:
            probes = [p for p in self.probes if p.name != "http"]

        self._log(f"[probe] running {len(tasks)} probe task(s) "
                  f"(mode={self.config.mode})…")

        def run_task(task):
            host = self.graph.get(task.target)
            if host is None or task.port not in host.ports:
                return
            port = host.ports[task.port]
            # already confirmed as a web service by httpx -> no generic banner grab
            confirmed = bool(httpx_web) and (host.ip, port.number) in httpx_web
            for probe in probes:
                if not probe.matches(port):
                    continue
                # a probe "confirms" when it identifies the service without error;
                # e.g. an HTTP GET that fails on a non-web port does NOT confirm.
                if self._run_probe_safe(probe, host, port):
                    confirmed = True
            # nothing positively identified the service -> generic banner grab,
            # so a port isn't left completely uncharacterised.
            if not confirmed:
                self._run_probe_safe(self.generic, host, port)

        total = len(tasks)
        with ThreadPoolExecutor(max_workers=max(2, self.config.concurrency // 4)) as pool:
            futures = [pool.submit(run_task, t) for t in tasks]
            for _ in as_completed(futures):
                self.progress.bump(total, "services tested")
        self._log(f"[probe] complete — {len(self.graph.all_http_services())} "
                  "HTTP service(s) analysed")

    def _httpx_active(self) -> bool:
        return self.httpx is not None and self.httpx.available()

    def _run_httpx_bulk(self):
        """Bulk-fingerprint candidate web endpoints with httpx. Returns the set of
        (ip, port) confirmed as web (services populated on the graph), or None to
        fall back to the built-in probe."""
        from .services import is_probably_http

        index: dict[str, tuple] = {}     # "ip:port" -> (host, port)
        for host in self.graph.hosts.values():
            for port in host.open_ports():
                if not is_probably_http(port):
                    continue
                if not self.scope.authorize(host.ip, port.number).allowed:
                    continue
                index[f"{host.ip}:{port.number}"] = (host, port)
        if not index:
            return set()

        self._log(f"[http] bulk-probing {len(index)} candidate web endpoint(s) "
                  "via httpx…")
        records, res = self.httpx.probe(
            sorted(index), timeout=int(self.config.timeout),
            threads=self.config.concurrency, rate=self.config.rate)
        if res.not_found:
            self._log("[http] httpx not usable — using built-in HTTP probe")
            return None

        httpprobe = next((p for p in self.probes if p.name == "http"), None)
        confirmed: set = set()
        added = 0
        for rec in records:
            key = str(rec.get("input") or rec.get("host") or "")
            hp = index.get(key)
            if hp is None:                # try to recover ip:port from the url
                continue
            host, port = hp
            svc = self.httpx.to_http_service(rec, host.ip, port.number)
            host.http_services.append(svc)
            # stamp the confirmed identity on the port
            port.service.name = "https" if svc.scheme == "https" else "http"
            port.service.confidence = self._high_conf()
            port.service.evidence = f"httpx: HTTP {svc.status}"
            # safe misconfig checks (OPTIONS/TRACE/dir-listing) that httpx doesn't do
            if httpprobe is not None:
                for f in httpprobe.misconfig(host, port, svc):
                    host.add_finding(f)
            confirmed.add((host.ip, port.number))
            added += 1
        self._log(f"[http] httpx confirmed {added} web service(s) of {len(index)} "
                  "candidate(s)")
        return confirmed

    @staticmethod
    def _high_conf():
        from .models import Confidence
        return Confidence.HIGH

    def _run_probe_safe(self, probe, host, port) -> bool:
        """Run one probe; add its findings. Returns True if it positively
        identified the service (no error), False otherwise. Never crashes."""
        try:
            result = probe.probe(host, port)
        except Exception as exc:  # defensive: a probe bug must not kill the run
            host.notes.append(f"probe {probe.name} error on {port.number}: {exc}")
            return False
        if result.error:
            return False
        for f in result.findings:
            host.add_finding(f)
        return True

    def _phase_content(self):
        if self.content is None:
            return
        services = self.graph.all_http_services()

        # Service-aware gate: content discovery applies ONLY to ports confirmed as
        # HTTP/HTTPS by the probe stage. Summarise the non-web open ports we
        # intentionally skip (they were assessed by their protocol probes).
        web_ports = {(s.ip, s.port) for _h, s in services}
        skipped: dict[str, int] = {}
        for host in self.graph.hosts.values():
            for p in host.open_ports():
                if (host.ip, p.number) in web_ports:
                    continue
                proto = p.service.name or "unknown"
                skipped[proto] = skipped.get(proto, 0) + 1

        if not services:
            self._log("[content] no HTTP/HTTPS service identified — content "
                      "discovery is not applicable to the open ports found")
            if skipped:
                self._log("[content] non-web ports assessed by protocol probes: "
                          + ", ".join(f"{k}×{v}" for k, v in sorted(skipped.items())))
            return

        use_ferox = self.ferox is not None and self.ferox.available()
        if self.ferox is not None and not use_ferox:
            self._log("[content] feroxbuster requested but not found on PATH — "
                      "falling back to built-in probe")

        backend = "feroxbuster" if use_ferox else "built-in"
        web_list = ", ".join(sorted(f"{ip}:{port}" for ip, port in web_ports))
        self._log(f"[content] {len(services)} web service(s) qualify for content "
                  f"discovery: {web_list}")
        if skipped:
            self._log(f"[content] skipping {sum(skipped.values())} non-web port(s): "
                      + ", ".join(f"{k}×{v}" for k, v in sorted(skipped.items())))
        self._log(f"[content] enumerating web content via {backend}…")

        from .content_discovery import _vhost_of
        added = 0
        sni_passes = 0
        total = len(services)
        for idx, (host, svc) in enumerate(services, 1):
            # Mandatory scope gate before handing a target to any tool.
            if self.scope.authorize(host.ip, svc.port).allowed:
                # HTTPS virtual hosts need TLS SNI = the vhost name, which
                # feroxbuster can't set while pinned to the IP. Use the built-in
                # SNI-aware pass for those; feroxbuster for everything else.
                is_tls_vhost = (svc.scheme == "https"
                                and bool(_vhost_of(svc, svc.ip)))
                try:
                    if use_ferox and not is_tls_vhost:
                        findings = self._run_ferox(host, svc)
                    else:
                        if use_ferox and is_tls_vhost:
                            sni_passes += 1
                        findings = self.content.scan_service(host, svc)
                except Exception as exc:
                    host.notes.append(f"content discovery error on {svc.port}: {exc}")
                    findings = []
                for f in findings:
                    before = len(host.findings)
                    host.add_finding(f)
                    if len(host.findings) > before:
                        added += 1
            self.progress.items(idx, total, "web services")
        note = (f" ({sni_passes} HTTPS vhost(s) via SNI-aware built-in pass)"
                if sni_passes else "")
        self._log(f"[content] {added} path finding(s) added{note}")

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
        total = len(services)
        for idx, (host, svc) in enumerate(services, 1):
            try:
                for f in self.vhost.probe_service(host, svc):
                    before = len(host.findings)
                    host.add_finding(f)
                    if len(host.findings) > before:
                        added += 1
            except Exception as exc:
                host.notes.append(f"vhost probe error on {svc.port}: {exc}")
            self.progress.items(idx, total, "TLS services")
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
        total = len(targets)
        for idx, ip in enumerate(targets, 1):
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
            self.progress.items(idx, total, "hosts")
        self._log(f"[udp] {open_count} open UDP port(s), {findings} finding(s) added")

    def _phase_domains(self):
        from .domains import collect_domains
        total = 0
        for host in self.graph.hosts.values():
            host.domains = collect_domains(host)
            total += len(host.domains)
        self._log(f"[domains] collected {total} unique hostname(s) across all hosts "
                  "(reverse DNS + TLS SAN/CN + redirects + vhosts)")

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

    def _phase_validate(self):
        if not getattr(self.config, "validate", True):
            self._log("[validate] disabled")
            return
        from .validation import ValidationEngine
        engine = ValidationEngine.from_config(self.config)
        cred = any(v.name == "credentialed" for v in engine.validators)
        mode = "applicability + non-destructive" + (" + credentialed" if cred else "")
        self._log(f"[validate] assessing findings ({mode})…")
        counts = engine.validate_graph(self.graph)
        self._log(f"[validate] {counts['touched']} finding(s) assessed — "
                  f"{counts['validated']} validated "
                  f"({counts['credentialed']} credentialed), "
                  f"{counts['downgraded']} demoted to unconfirmed")

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
            remaining = max(0, total - done)
            sys.stdout.write(f"\r[{label}] {done}/{total} ({pct}%) - "
                             f"{remaining} remaining     ")
            if done >= total:
                sys.stdout.write("\n")
            sys.stdout.flush()
        return cb

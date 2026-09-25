"""Live-host discovery.

ICMP is often blocked and requires raw-socket privileges, so the default
technique is TCP-connect probing against a small set of common ports. A host
that answers on any probe port is LIVE. A host that refuses (RST) is also proof
of life (something is there). Only hosts that give nothing back are marked
UNRESPONSIVE — never assumed truly offline, because filtering is common.

Every probe passes through the Scope Engine.
"""
from __future__ import annotations

import socket
import time
from concurrent.futures import ThreadPoolExecutor, as_completed
from typing import Callable, Optional

from .config import Config
from .models import Host, HostStatus
from .scope import ScopeEngine


class DiscoveryEngine:
    def __init__(self, config: Config, scope: ScopeEngine):
        self.config = config
        self.scope = scope

    def _tcp_probe(self, ip: str, port: int) -> tuple[str, float]:
        """Return ('open'|'refused'|'filtered', latency_ms)."""
        start = time.monotonic()
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(self.config.timeout)
        try:
            sock.connect((ip, port))
            return "open", (time.monotonic() - start) * 1000.0
        except ConnectionRefusedError:
            return "refused", (time.monotonic() - start) * 1000.0
        except (socket.timeout, OSError):
            return "filtered", 0.0
        finally:
            try:
                sock.close()
            except OSError:
                pass

    def discover_host(self, ip: str) -> Host:
        host = Host(ip=ip)
        if self.config.skip_discovery:
            host.status = HostStatus.LIVE
            host.discovery_method = "assumed (discovery skipped)"
            return host

        best_latency: Optional[float] = None
        method = ""
        saw_refused = False
        saw_filtered = False

        for port in self.config.discovery_ports:
            with self.scope.slot(ip, port) as s:
                if not s.allowed:
                    continue
                result, latency = self._tcp_probe(ip, port)
            if result == "open":
                host.status = HostStatus.LIVE
                method = f"tcp-connect:{port}"
                best_latency = latency
                break
            elif result == "refused":
                saw_refused = True
                if best_latency is None:
                    best_latency = latency
                    method = f"tcp-rst:{port}"
            else:
                saw_filtered = True

        if host.status != HostStatus.LIVE:
            if saw_refused:
                host.status = HostStatus.LIVE   # RST proves a host exists
                host.notes.append("alive via TCP RST (ports closed but host up)")
            elif saw_filtered:
                host.status = HostStatus.FILTERED
                host.notes.append("all probe ports filtered — may be firewalled, not offline")
            else:
                host.status = HostStatus.UNRESPONSIVE

        host.discovery_method = method or "tcp-connect(no response)"
        # note: 0.0 is a valid (sub-ms) latency, so test for None explicitly
        host.latency_ms = round(best_latency, 2) if best_latency is not None else None
        return host

    def discover(self, ips: list[str],
                 progress: Optional[Callable[[int, int], None]] = None
                 ) -> list[Host]:
        results: list[Host] = []
        total = len(ips)
        done = 0
        with ThreadPoolExecutor(max_workers=self.config.concurrency) as pool:
            futures = {pool.submit(self.discover_host, ip): ip for ip in ips}
            for fut in as_completed(futures):
                done += 1
                if progress:
                    progress(done, total)
                results.append(fut.result())
        results.sort(key=lambda h: tuple(int(x) for x in h.ip.split(".")) if h.ip.count(".") == 3 else (0,))
        return results

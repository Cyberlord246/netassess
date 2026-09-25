"""Port scanning.

Two backends:
  * NmapAdapter (when nmap is installed) — richer service/version detection.
  * PurePythonScanner — TCP connect scan using stdlib sockets, always available.

Both go through the Scope Engine for every single connection. The pure-Python
scanner respects concurrency, rate, timeout and retry policy.
"""
from __future__ import annotations

import socket
import time
from concurrent.futures import ThreadPoolExecutor, as_completed
from typing import Callable, Optional

from .config import Config
from .models import Confidence, Port, PortState, Service
from .scope import ScopeEngine


# Ports where grabbing a banner by simply connecting is safe & useful.
# For HTTP-like ports we send a minimal, well-formed HEAD-ish probe elsewhere.
_BANNER_READ_PORTS = {21, 22, 25, 110, 143, 3306, 5432, 6379, 11211, 27017, 587, 465}


class PurePythonScanner:
    """TCP connect scanner (stdlib only)."""

    def __init__(self, config: Config, scope: ScopeEngine):
        self.config = config
        self.scope = scope

    def _connect_once(self, ip: str, port: int) -> tuple[PortState, float, str]:
        """Attempt a single TCP connect. Returns (state, latency_ms, banner)."""
        start = time.monotonic()
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(self.config.timeout)
        try:
            sock.connect((ip, port))
            latency = (time.monotonic() - start) * 1000.0
            banner = ""
            if self.config.service_detection != "off" and port in _BANNER_READ_PORTS:
                banner = self._read_banner(sock, port)
            return PortState.OPEN, latency, banner
        except socket.timeout:
            return PortState.FILTERED, 0.0, ""
        except ConnectionRefusedError:
            return PortState.CLOSED, 0.0, ""
        except OSError:
            return PortState.FILTERED, 0.0, ""
        finally:
            try:
                sock.close()
            except OSError:
                pass

    def _read_banner(self, sock: socket.socket, port: int) -> str:
        try:
            sock.settimeout(min(self.config.timeout, 2.0))
            # Some services speak first (SSH, SMTP, FTP, Redis-PING-less). For the
            # rest we send a benign newline to elicit a greeting.
            if port in (6379,):
                sock.sendall(b"PING\r\n")
            data = sock.recv(256)
            return data.decode("latin-1", errors="replace").strip()
        except OSError:
            return ""

    def scan_port(self, ip: str, port: int) -> Optional[Port]:
        """Scope-gated scan of one port with retries."""
        attempts = 1 + max(0, self.config.retries)
        last_state = PortState.FILTERED
        for _ in range(attempts):
            with self.scope.slot(ip, port) as s:
                if not s.allowed:
                    return None  # scope denied — never touched the network
                state, latency, banner = self._connect_once(ip, port)
            last_state = state
            if state == PortState.OPEN:
                svc = Service(protocol="tcp", banner=banner)
                if banner:
                    svc.evidence = "tcp banner"
                return Port(number=port, protocol="tcp", state=PortState.OPEN,
                            service=svc, latency_ms=round(latency, 2))
            if state == PortState.CLOSED:
                return None  # definitive; no retry needed
        return None if last_state != PortState.OPEN else None

    def scan_host(self, ip: str, ports: list[int],
                  progress: Optional[Callable[[int, int], None]] = None
                  ) -> list[Port]:
        found: list[Port] = []
        total = len(ports)
        done = 0
        with ThreadPoolExecutor(max_workers=self.config.concurrency) as pool:
            futures = {pool.submit(self.scan_port, ip, p): p for p in ports}
            for fut in as_completed(futures):
                done += 1
                if progress:
                    progress(done, total)
                port = fut.result()
                if port is not None:
                    found.append(port)
        found.sort(key=lambda p: p.number)
        return found


class PortScanner:
    """Front door: prefers nmap when available, else pure-python."""

    def __init__(self, config: Config, scope: ScopeEngine, nmap_adapter=None):
        self.config = config
        self.scope = scope
        self.nmap = nmap_adapter
        self.pure = PurePythonScanner(config, scope)
        self.backend = "nmap" if (nmap_adapter and nmap_adapter.available()) else "python"

    def scan_host(self, ip: str, ports: Optional[list[int]] = None,
                  progress: Optional[Callable[[int, int], None]] = None
                  ) -> list[Port]:
        ports = ports if ports is not None else self.config.effective_ports()
        # Filter to scope-authorized ports up front (policy: forbidden ports).
        ports = [p for p in ports if self.scope.authorize(ip, p).allowed]
        if not ports:
            return []

        if self.backend == "nmap":
            nmap_ports, res = self.nmap.scan(
                ip, ports, timeout=max(60.0, self.config.timeout * len(ports) / 10),
                service_detection=self.config.service_detection,
            )
            if res.ok or nmap_ports:
                return nmap_ports
            # nmap failed -> graceful fallback to python
        return self.pure.scan_host(ip, ports, progress)

    def scan_hosts(self, targets: list[str], ports: Optional[list[int]] = None,
                   progress: Optional[Callable[[int, int], None]] = None
                   ) -> dict[str, list[Port]]:
        """Scan many hosts concurrently, bounded by the global concurrency/rate
        budget (the scope engine's shared semaphore + token bucket cap total
        in-flight connections regardless of how many hosts run at once).

        - python backend: flatten every (host, port) into ONE bounded thread
          pool sized to ``concurrency`` — keeps the budget fully utilised across
          all hosts instead of draining one host at a time, with no thread
          explosion (exactly ``concurrency`` workers total).
        - nmap backend: run per-host nmap invocations in parallel (each is its
          own process with internal timing), capped to a modest worker count.
        """
        ports = ports if ports is not None else self.config.effective_ports()
        results: dict[str, list[Port]] = {ip: [] for ip in targets}
        if not targets or not ports:
            return results

        if self.backend == "nmap":
            workers = max(1, min(len(targets), 16))

            def _one(ip: str):
                allowed = [p for p in ports if self.scope.authorize(ip, p).allowed]
                if not allowed:
                    return ip, []
                nmap_ports, res = self.nmap.scan(
                    ip, allowed,
                    timeout=max(60.0, self.config.timeout * len(allowed) / 10),
                    service_detection=self.config.service_detection,
                )
                if res.ok or nmap_ports:
                    return ip, nmap_ports
                return ip, self.pure.scan_host(ip, allowed)   # fallback

            done = 0
            with ThreadPoolExecutor(max_workers=workers) as pool:
                for fut in as_completed({pool.submit(_one, ip): ip for ip in targets}):
                    ip, found = fut.result()
                    results[ip] = found
                    done += 1
                    if progress:
                        progress(done, len(targets))
        else:
            # flatten (host, port) across all hosts into one bounded pool
            pairs = [(ip, p) for ip in targets for p in ports]
            total = len(pairs)
            done = 0
            with ThreadPoolExecutor(max_workers=max(1, self.config.concurrency)) as pool:
                futures = {pool.submit(self.pure.scan_port, ip, p): ip
                           for ip, p in pairs}
                for fut in as_completed(futures):
                    ip = futures[fut]
                    done += 1
                    if progress:
                        progress(done, total)
                    port = fut.result()
                    if port is not None:
                        results[ip].append(port)

        for ip in results:
            results[ip].sort(key=lambda p: p.number)
        return results

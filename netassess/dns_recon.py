"""Reverse DNS resolution.

PTR lookups are performed against the resolver configured on the host. A PTR
record is recorded as evidence only — a hostname is NEVER treated as proof of
ownership or organisational affiliation (that requires independent verification).

Reverse DNS queries the resolver, not the target host, so they are low-touch;
we still record status and timestamp for every lookup.
"""
from __future__ import annotations

import socket
from concurrent.futures import ThreadPoolExecutor, as_completed

from .models import iso


class ReverseDNS:
    def __init__(self, timeout: float = 3.0):
        self.timeout = timeout

    def lookup(self, ip: str) -> dict:
        socket.setdefaulttimeout(self.timeout)
        rec = {"ip": ip, "hostnames": [], "status": "no_record", "ts": iso()}
        try:
            primary, aliases, _addrs = socket.gethostbyaddr(ip)
            names = [primary] + [a for a in aliases if a != primary]
            rec["hostnames"] = names
            rec["status"] = "resolved"
        except (socket.herror, socket.gaierror):
            rec["status"] = "no_record"
        except (socket.timeout, OSError) as exc:
            rec["status"] = f"error:{exc}"
        return rec

    def lookup_many(self, ips: list[str], concurrency: int = 20) -> dict[str, dict]:
        out: dict[str, dict] = {}
        with ThreadPoolExecutor(max_workers=max(1, concurrency)) as pool:
            futures = {pool.submit(self.lookup, ip): ip for ip in ips}
            for fut in as_completed(futures):
                rec = fut.result()
                out[rec["ip"]] = rec
        return out

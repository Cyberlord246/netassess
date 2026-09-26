"""Consolidated domain/hostname collection.

Gathers every hostname discovered for a host from ALL sources — reverse DNS
(PTR), TLS certificate SAN + CN, HTTP redirect targets, and virtual-host probing
— de-duplicates them, and records where each was seen (provenance). Pure analysis
over the asset graph; no network.
"""
from __future__ import annotations

import ipaddress
import re
from urllib.parse import urlparse

_CN_RE = re.compile(r"(?:commonName|CN)=([^,]+)", re.I)
_URL_RE = re.compile(r"https?://[^\s'\")]+", re.I)


def _is_ip(value: str) -> bool:
    try:
        ipaddress.ip_address(value)
        return True
    except ValueError:
        return False


def _norm(name: str) -> str:
    return (name or "").strip().lower().rstrip(".")


def collect_domains(host) -> dict[str, list[str]]:
    """Return {hostname: [sources...]} for one host, from every source."""
    found: dict[str, set[str]] = {}

    def add(name: str, source: str):
        n = _norm(name)
        if not n or _is_ip(n) or n == host.ip:
            return
        found.setdefault(n, set()).add(source)

    # 1) reverse DNS (PTR)
    for hn in host.hostnames:
        add(hn, "reverse-dns (PTR)")

    # 2) TLS certificate SAN + CN (per port, from TLSProbe)
    for port, tls in host.tls.items():
        for san in tls.sans or []:
            add(san, f"TLS SAN (:{port})")
        m = _CN_RE.search(tls.subject or "")
        if m:
            add(m.group(1), f"TLS CN (:{port})")

    # 3) HTTP services: their own TLS, redirect targets, and vhost URL names
    for svc in host.http_services:
        if svc.tls:
            for san in svc.tls.sans or []:
                add(san, f"TLS SAN (:{svc.port})")
            m = _CN_RE.search(svc.tls.subject or "")
            if m:
                add(m.group(1), f"TLS CN (:{svc.port})")
        # redirect Location targets (e.g. "301 -> https://www.example.com/")
        for hop in svc.redirect_chain or []:
            for url in _URL_RE.findall(hop):
                h = urlparse(url).hostname
                if h:
                    add(h, "HTTP redirect")
        # a vhost entry's URL carries a hostname (from --vhosts)
        u = urlparse(svc.url)
        if u.hostname and not _is_ip(u.hostname):
            add(u.hostname, "virtual host")

    return {name: sorted(src) for name, src in sorted(found.items())}


def all_domains(graph) -> list[tuple[str, list[str], list[str]]]:
    """Global view: [(domain, sources, [ips it was seen on])], sorted."""
    agg: dict[str, tuple[set[str], set[str]]] = {}
    for host in graph.hosts.values():
        for name, sources in (host.domains or {}).items():
            srcs, ips = agg.setdefault(name, (set(), set()))
            srcs.update(sources)
            ips.add(host.ip)
    return [(name, sorted(s), sorted(i)) for name, (s, i) in sorted(agg.items())]

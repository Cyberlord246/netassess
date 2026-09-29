"""Forward DNS resolution of user-supplied hostname targets.

The Scope Engine authorises IPs/CIDRs. When the operator provides *hostnames*
(the common case for a web attack-surface assessment against a domain list),
those names are explicitly authorised by the operator, so we resolve them to
IPs here and feed those IPs into scope — while remembering which hostname(s)
map to each IP so the HTTP probe can use them as Host/SNI and the report can
attribute findings back to the domain.

This is NOT the same as auto-adding discovered hosts: only names the operator
listed are resolved. Input is also cleaned (URL scheme/path stripped, and the
occasional markdown ``[name](url)`` entry unwrapped) so a messy list still works.
"""
from __future__ import annotations

import ipaddress
import re
import socket
from concurrent.futures import ThreadPoolExecutor, as_completed
from dataclasses import dataclass, field
from typing import Callable, Optional

_MD_LINK = re.compile(r"^\[([^\]]+)\]\(([^)]+)\)$")
_SCHEME = re.compile(r"^[a-zA-Z][a-zA-Z0-9+.\-]*://")


def clean_target(raw: str) -> str:
    """Normalise one raw target line to a bare IP/CIDR or hostname.

    Handles: comments, surrounding whitespace, markdown ``[text](url)`` links,
    URL schemes, paths/queries/fragments, userinfo, and :port suffixes.
    """
    s = (raw or "").strip()
    if not s or s.startswith("#"):
        return ""
    m = _MD_LINK.match(s)
    if m:                       # markdown link -> prefer the URL in (), else text
        s = (m.group(2) or m.group(1)).strip()
    s = _SCHEME.sub("", s)      # strip scheme://
    if is_ip_or_cidr(s):        # a bare IP/CIDR is already clean (keep the /prefix)
        return s.lower()
    for sep in ("/", "?", "#"):
        if sep in s:
            s = s.split(sep, 1)[0]
    if "@" in s:                # strip userinfo
        s = s.rsplit("@", 1)[1]
    if s.startswith("["):       # [IPv6](:port)
        end = s.find("]")
        if end != -1:
            return s[1:end].strip().lower()
    if "/" not in s and s.count(":") == 1:   # host:port (not bare IPv6)
        s = s.split(":", 1)[0]
    return s.strip().rstrip(".").lower()


def is_ip_or_cidr(s: str) -> bool:
    try:
        if "/" in s:
            ipaddress.ip_network(s, strict=False)
        else:
            ipaddress.ip_address(s)
        return True
    except ValueError:
        return False


def _resolve_one(name: str, timeout: float) -> tuple[str, list[str], str]:
    """Resolve a hostname to IPs (IPv4 preferred; IPv6 only if no IPv4)."""
    socket.setdefaulttimeout(timeout)
    try:
        infos = socket.getaddrinfo(name, None)
    except (socket.gaierror, socket.herror, OSError) as exc:
        return name, [], str(exc)
    v4 = sorted({i[4][0] for i in infos if i[0] == socket.AF_INET})
    v6 = sorted({i[4][0] for i in infos if i[0] == socket.AF_INET6})
    return name, (v4 or v6), ""


@dataclass
class ResolvedScope:
    ip_targets: list[str] = field(default_factory=list)   # IPs/CIDRs for scope
    host_map: dict[str, list[str]] = field(default_factory=dict)   # ip -> hostnames
    name_to_ips: dict[str, list[str]] = field(default_factory=dict)
    unresolved: list[str] = field(default_factory=list)
    domains: list[str] = field(default_factory=list)      # hostnames provided
    changed: bool = False                                 # any hostname/cleanup applied


def expand_targets(raw_targets: list[str], timeout: float = 3.0,
                   concurrency: int = 50,
                   resolver: Optional[Callable[[str, float], tuple]] = None
                   ) -> ResolvedScope:
    """Clean + classify targets; resolve hostnames to IPs concurrently."""
    resolver = resolver or _resolve_one
    ips: list[str] = []
    hostnames: list[str] = []
    changed = False
    for raw in raw_targets:
        c = clean_target(raw)
        if not c:
            continue
        if c != (raw or "").strip().lower():
            changed = True
        if is_ip_or_cidr(c):
            ips.append(c)
        else:
            hostnames.append(c)
            changed = True

    hostnames = sorted(set(hostnames))
    host_map: dict[str, set] = {}
    name_to_ips: dict[str, list[str]] = {}
    unresolved: list[str] = []

    if hostnames:
        with ThreadPoolExecutor(max_workers=max(1, min(concurrency, 100))) as pool:
            futs = [pool.submit(resolver, n, timeout) for n in hostnames]
            for f in as_completed(futs):
                name, rips, _err = f.result()
                if rips:
                    name_to_ips[name] = rips
                    for ip in rips:
                        host_map.setdefault(ip, set()).add(name)
                        ips.append(ip)
                else:
                    unresolved.append(name)

    return ResolvedScope(
        ip_targets=sorted(set(ips)),
        host_map={ip: sorted(names) for ip, names in host_map.items()},
        name_to_ips=name_to_ips,
        unresolved=sorted(unresolved),
        domains=hostnames,
        changed=changed,
    )

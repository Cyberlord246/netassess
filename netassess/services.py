"""Service identification.

Combines two evidence sources, never port number alone:
  1. A default port -> service hint (low confidence).
  2. Banner / probe evidence (raises confidence, can override the hint).

The result annotates each Port's Service in place.
"""
from __future__ import annotations

import re

from .models import Confidence, Port, Service


# port -> (service name, typical scheme). Hints only; low confidence.
PORT_HINTS: dict[int, str] = {
    21: "ftp", 22: "ssh", 23: "telnet", 25: "smtp", 53: "dns",
    80: "http", 110: "pop3", 111: "rpcbind", 135: "msrpc", 139: "netbios-ssn",
    143: "imap", 161: "snmp", 389: "ldap", 443: "https", 445: "smb",
    465: "smtps", 587: "smtp-submission", 636: "ldaps", 993: "imaps",
    995: "pop3s", 1433: "mssql", 1521: "oracle", 2049: "nfs",
    2375: "docker", 3000: "http-alt", 3306: "mysql", 3389: "rdp",
    5432: "postgresql", 5601: "kibana", 5900: "vnc", 5985: "winrm",
    6379: "redis", 8000: "http-alt", 8080: "http-proxy", 8443: "https-alt",
    8888: "http-alt", 9200: "elasticsearch", 9300: "elasticsearch",
    11211: "memcached", 27017: "mongodb",
}

HTTP_SERVICES = {"http", "https", "http-alt", "http-proxy", "https-alt"}
TLS_SERVICES = {"https", "https-alt", "smtps", "imaps", "pop3s", "ldaps"}

# banner signatures -> (service, product regex for version extraction)
_BANNER_SIGS: list[tuple[re.Pattern, str, str]] = [
    (re.compile(r"^SSH-([\d.]+)-(.+)", re.I), "ssh", r"SSH-[\d.]+-(.+)"),
    (re.compile(r"^220[ -].*(smtp|postfix|exim|sendmail)", re.I), "smtp", ""),
    (re.compile(r"^220[ -].*ftp", re.I), "ftp", ""),
    (re.compile(r"redis_version:([\d.]+)", re.I), "redis", r"redis_version:([\d.]+)"),
    (re.compile(r"-ERR|^\+PONG", re.I), "redis", ""),
    (re.compile(r"^\*.*mongodb", re.I), "mongodb", ""),
    (re.compile(r"mysql_native_password|\x0amysql", re.I), "mysql", ""),
]


def identify(port: Port) -> Service:
    svc = port.service
    hint = PORT_HINTS.get(port.number)

    # Start from the hint if the scanner didn't already name it.
    if svc.name in ("", "unknown") and hint:
        svc.name = hint
        svc.confidence = Confidence.LOW
        svc.evidence = f"default port {port.number}"

    banner = svc.banner or ""
    if banner:
        for pat, name, ver_re in _BANNER_SIGS:
            if pat.search(banner):
                svc.name = name
                svc.confidence = Confidence.HIGH
                svc.evidence = "banner match"
                if ver_re:
                    m = re.search(ver_re, banner, re.I)
                    if m:
                        svc.product = m.group(1).strip()
                break
        else:
            # We have a banner but no known signature: medium confidence in hint.
            if svc.name and svc.name != "unknown":
                svc.confidence = Confidence.MEDIUM

    # nmap-provided product/version already gives high confidence; keep it.
    if svc.product and svc.confidence == Confidence.LOW:
        svc.confidence = Confidence.MEDIUM

    return svc


def is_http(port: Port) -> bool:
    name = port.service.name
    if name in HTTP_SERVICES:
        return True
    # common alt ports even if unnamed
    return port.number in (80, 443, 3000, 5601, 8000, 8080, 8443, 8888, 9200)


def is_tls(port: Port) -> bool:
    return (port.service.name in TLS_SERVICES
            or port.number in (443, 465, 636, 993, 995, 8443))


def default_scheme(port: Port) -> str:
    return "https" if is_tls(port) else "http"

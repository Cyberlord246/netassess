"""Persistent, queryable asset graph.

Holds every discovered Host and its ports/services/http/tls/findings. Thread
safe for concurrent updates. Serialises to a single JSON file so an assessment
can be resumed, diffed, or fed to the report generator.
"""
from __future__ import annotations

import json
import os
import threading
from typing import Callable, Iterable, Optional

from .models import (
    Finding, Host, HostStatus, HTTPService, Port, Service, TLSInfo,
    Technology, Confidence, PortState, Severity, ValidationState, iso,
)


class AssetGraph:
    def __init__(self):
        self.hosts: dict[str, Host] = {}
        self._lock = threading.RLock()
        self.started: str = iso()
        self.meta: dict = {}

    # -- host access ------------------------------------------------------ #
    def get_or_create(self, ip: str) -> Host:
        with self._lock:
            host = self.hosts.get(ip)
            if host is None:
                host = Host(ip=ip)
                self.hosts[ip] = host
            return host

    def get(self, ip: str) -> Optional[Host]:
        return self.hosts.get(ip)

    def update(self, ip: str, mutator: Callable[[Host], None]) -> Host:
        with self._lock:
            host = self.get_or_create(ip)
            mutator(host)
            host.touch()
            return host

    # -- queries ---------------------------------------------------------- #
    def live_hosts(self) -> list[Host]:
        return [h for h in self.hosts.values() if h.status == HostStatus.LIVE]

    def hosts_with_open_ports(self) -> list[Host]:
        return [h for h in self.hosts.values() if h.open_ports()]

    def iter_open_ports(self) -> Iterable[tuple[Host, Port]]:
        for h in self.hosts.values():
            for p in h.open_ports():
                yield h, p

    def all_findings(self) -> list[tuple[Host, Finding]]:
        out = []
        for h in self.hosts.values():
            for f in h.findings:
                out.append((h, f))
        return out

    def all_http_services(self) -> list[tuple[Host, HTTPService]]:
        out = []
        for h in self.hosts.values():
            for s in h.http_services:
                out.append((h, s))
        return out

    # -- persistence ------------------------------------------------------ #
    def to_dict(self) -> dict:
        with self._lock:
            return {
                "started": self.started,
                "saved": iso(),
                "meta": self.meta,
                "hosts": {ip: h.to_dict() for ip, h in self.hosts.items()},
            }

    def save(self, path: str) -> None:
        os.makedirs(os.path.dirname(os.path.abspath(path)), exist_ok=True)
        tmp = path + ".tmp"
        with self._lock:
            data = self.to_dict()
        with open(tmp, "w", encoding="utf-8") as fh:
            json.dump(data, fh, indent=2)
        os.replace(tmp, path)

    # -- deserialisation (resume / report) -------------------------------- #
    @classmethod
    def load(cls, path: str) -> "AssetGraph":
        with open(path, "r", encoding="utf-8") as fh:
            data = json.load(fh)
        g = cls()
        g.started = data.get("started", iso())
        g.meta = data.get("meta", {})
        for ip, hd in data.get("hosts", {}).items():
            g.hosts[ip] = _host_from_dict(hd)
        return g


# --------------------------------------------------------------------------- #
# dict -> model rebuilders
# --------------------------------------------------------------------------- #
def _service_from_dict(d: dict) -> Service:
    return Service(
        name=d.get("name", "unknown"),
        product=d.get("product", ""),
        version=d.get("version", ""),
        protocol=d.get("protocol", "tcp"),
        confidence=Confidence(d.get("confidence", "low")),
        banner=d.get("banner", ""),
        evidence=d.get("evidence", ""),
    )


def _port_from_dict(d: dict) -> Port:
    return Port(
        number=int(d["number"]),
        protocol=d.get("protocol", "tcp"),
        state=PortState(d.get("state", "open")),
        service=_service_from_dict(d.get("service", {})),
        latency_ms=d.get("latency_ms"),
        first_seen=d.get("first_seen", iso()),
    )


def _tls_from_dict(d: dict) -> TLSInfo:
    return TLSInfo(**d)


def _tech_from_dict(d: dict) -> Technology:
    return Technology(
        name=d["name"], version=d.get("version", ""),
        category=d.get("category", ""), evidence=d.get("evidence", ""),
        confidence=Confidence(d.get("confidence", "low")),
    )


def _http_from_dict(d: dict) -> HTTPService:
    tls = _tls_from_dict(d["tls"]) if d.get("tls") else None
    return HTTPService(
        url=d["url"], ip=d["ip"], port=int(d["port"]), scheme=d.get("scheme", "http"),
        status=d.get("status"), title=d.get("title", ""), server=d.get("server", ""),
        content_type=d.get("content_type", ""), content_length=d.get("content_length"),
        redirect_chain=d.get("redirect_chain", []), headers=d.get("headers", {}),
        security_headers=d.get("security_headers", {}),
        technologies=[_tech_from_dict(t) for t in d.get("technologies", [])],
        tls=tls, response_ms=d.get("response_ms"), favicon_hash=d.get("favicon_hash", ""),
        discovered_paths=d.get("discovered_paths", []),
    )


def _finding_from_dict(d: dict) -> Finding:
    return Finding(
        title=d["title"], asset=d["asset"], description=d.get("description", ""),
        evidence=d.get("evidence", ""), why_it_matters=d.get("why_it_matters", ""),
        severity=Severity(d.get("severity", "info")),
        confidence=Confidence(d.get("confidence", "low")),
        impact=d.get("impact", ""), remediation=d.get("remediation", ""),
        validation=ValidationState(d.get("validation", "OBSERVED")),
        source=d.get("source", "netassess"), category=d.get("category", "general"),
        ts=d.get("ts", iso()),
    )


def _host_from_dict(d: dict) -> Host:
    h = Host(ip=d["ip"])
    h.status = HostStatus(d.get("status", "UNKNOWN"))
    h.hostnames = d.get("hostnames", [])
    h.discovery_method = d.get("discovery_method", "")
    h.latency_ms = d.get("latency_ms")
    h.ports = {int(k): _port_from_dict(v) for k, v in d.get("ports", {}).items()}
    h.http_services = [_http_from_dict(x) for x in d.get("http_services", [])]
    h.findings = [_finding_from_dict(x) for x in d.get("findings", [])]
    h.tls = {int(k): _tls_from_dict(v) for k, v in d.get("tls", {}).items()}
    h.notes = d.get("notes", [])
    h.first_seen = d.get("first_seen", iso())
    h.last_updated = d.get("last_updated", iso())
    return h

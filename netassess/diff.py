"""Diff engine — compare two assessment runs (state.json files).

Turns two AssetGraph snapshots into a structured, security-focused delta:
newly opened/closed ports, new/removed hosts, service-version changes, and
new/resolved findings (including CVE leads). Useful for change monitoring and
re-tests: "what got worse since last time?"

Identity rules
--------------
* Host        : by IP.
* Port        : by (IP, port number).
* HTTP service: by URL.
* Finding     : by (asset, title) — the same de-dupe key the asset graph uses.
"""
from __future__ import annotations

import json
import os
from dataclasses import dataclass, field

from .models import SEVERITY_ORDER, Severity
from .state import AssetGraph


def _svc_desc(port) -> str:
    s = port.service
    parts = [s.name] + [x for x in (s.product, s.version) if x]
    return " ".join(parts).strip() or "unknown"


@dataclass
class DiffResult:
    old_label: str = ""
    new_label: str = ""
    hosts_added: list[str] = field(default_factory=list)
    hosts_removed: list[str] = field(default_factory=list)
    host_status_changed: list[tuple[str, str, str]] = field(default_factory=list)
    ports_opened: list[tuple[str, int, str]] = field(default_factory=list)
    ports_closed: list[tuple[str, int, str]] = field(default_factory=list)
    service_changed: list[tuple[str, int, str, str]] = field(default_factory=list)
    http_added: list[str] = field(default_factory=list)
    http_removed: list[str] = field(default_factory=list)
    findings_new: list[dict] = field(default_factory=list)
    findings_resolved: list[dict] = field(default_factory=list)

    def is_empty(self) -> bool:
        return not any([
            self.hosts_added, self.hosts_removed, self.host_status_changed,
            self.ports_opened, self.ports_closed, self.service_changed,
            self.http_added, self.http_removed, self.findings_new,
            self.findings_resolved,
        ])

    def counts(self) -> dict:
        return {
            "hosts_added": len(self.hosts_added),
            "hosts_removed": len(self.hosts_removed),
            "host_status_changed": len(self.host_status_changed),
            "ports_opened": len(self.ports_opened),
            "ports_closed": len(self.ports_closed),
            "service_changed": len(self.service_changed),
            "http_added": len(self.http_added),
            "http_removed": len(self.http_removed),
            "findings_new": len(self.findings_new),
            "findings_resolved": len(self.findings_resolved),
        }

    def to_dict(self) -> dict:
        return {
            "old": self.old_label, "new": self.new_label,
            "summary": self.counts(),
            "hosts_added": self.hosts_added,
            "hosts_removed": self.hosts_removed,
            "host_status_changed": [
                {"ip": ip, "from": a, "to": b}
                for ip, a, b in self.host_status_changed],
            "ports_opened": [
                {"ip": ip, "port": p, "service": s}
                for ip, p, s in self.ports_opened],
            "ports_closed": [
                {"ip": ip, "port": p, "service": s}
                for ip, p, s in self.ports_closed],
            "service_changed": [
                {"ip": ip, "port": p, "from": a, "to": b}
                for ip, p, a, b in self.service_changed],
            "http_added": self.http_added,
            "http_removed": self.http_removed,
            "findings_new": self.findings_new,
            "findings_resolved": self.findings_resolved,
        }


def diff_graphs(old: AssetGraph, new: AssetGraph,
                old_label: str = "old", new_label: str = "new") -> DiffResult:
    d = DiffResult(old_label=old_label, new_label=new_label)
    old_ips, new_ips = set(old.hosts), set(new.hosts)

    d.hosts_added = sorted(new_ips - old_ips)
    d.hosts_removed = sorted(old_ips - new_ips)

    for ip in sorted(new_ips & old_ips):
        oh, nh = old.hosts[ip], new.hosts[ip]
        if oh.status != nh.status:
            d.host_status_changed.append((ip, oh.status.value, nh.status.value))

    # ports (across all hosts present in either snapshot)
    for ip in sorted(new_ips | old_ips):
        oh = old.hosts.get(ip)
        nh = new.hosts.get(ip)
        old_ports = {p.number: p for p in (oh.open_ports() if oh else [])}
        new_ports = {p.number: p for p in (nh.open_ports() if nh else [])}
        for num in sorted(set(new_ports) - set(old_ports)):
            d.ports_opened.append((ip, num, _svc_desc(new_ports[num])))
        for num in sorted(set(old_ports) - set(new_ports)):
            d.ports_closed.append((ip, num, _svc_desc(old_ports[num])))
        for num in sorted(set(old_ports) & set(new_ports)):
            a, b = _svc_desc(old_ports[num]), _svc_desc(new_ports[num])
            if a != b:
                d.service_changed.append((ip, num, a, b))

    # http services (by URL)
    old_urls = {s.url for _h, s in old.all_http_services()}
    new_urls = {s.url for _h, s in new.all_http_services()}
    d.http_added = sorted(new_urls - old_urls)
    d.http_removed = sorted(old_urls - new_urls)

    # findings (by asset+title)
    def _fmap(g):
        m = {}
        for _h, f in g.all_findings():
            m[(f.asset, f.title)] = f
        return m

    old_f, new_f = _fmap(old), _fmap(new)
    for key in new_f.keys() - old_f.keys():
        f = new_f[key]
        d.findings_new.append({
            "asset": f.asset, "title": f.title, "severity": f.severity.value,
            "validation": f.validation.value, "source": f.source,
            "category": f.category})
    for key in old_f.keys() - new_f.keys():
        f = old_f[key]
        d.findings_resolved.append({
            "asset": f.asset, "title": f.title, "severity": f.severity.value})

    # sort findings by severity (most severe first)
    d.findings_new.sort(key=lambda x: SEVERITY_ORDER[Severity(x["severity"])],
                        reverse=True)
    d.findings_resolved.sort(key=lambda x: SEVERITY_ORDER[Severity(x["severity"])],
                             reverse=True)
    return d


# --------------------------------------------------------------------------- #
# rendering (ASCII markers only — safe on any console encoding)
# --------------------------------------------------------------------------- #
def render_markdown(d: DiffResult) -> str:
    s: list[str] = []
    w = s.append
    w("# Assessment Diff\n")
    w(f"- **Baseline (old):** `{d.old_label}`")
    w(f"- **Current (new):** `{d.new_label}`\n")

    if d.is_empty():
        w("_No changes detected between the two runs._\n")
        return "\n".join(s)

    c = d.counts()
    w("## Summary\n")
    w("| Change | Count |")
    w("|---|---|")
    labels = [
        ("Hosts added", "hosts_added"), ("Hosts removed", "hosts_removed"),
        ("Host status changed", "host_status_changed"),
        ("Ports opened", "ports_opened"), ("Ports closed", "ports_closed"),
        ("Service/version changed", "service_changed"),
        ("HTTP services added", "http_added"),
        ("HTTP services removed", "http_removed"),
        ("New findings", "findings_new"),
        ("Resolved findings", "findings_resolved"),
    ]
    for label, key in labels:
        if c[key]:
            w(f"| {label} | {c[key]} |")

    if d.ports_opened:
        w("\n## [+] Newly Opened Ports\n")
        for ip, port, svc in d.ports_opened:
            w(f"- `{ip}:{port}` -> {svc}")
    if d.ports_closed:
        w("\n## [-] Newly Closed Ports\n")
        for ip, port, svc in d.ports_closed:
            w(f"- `{ip}:{port}` -> {svc}")

    if d.service_changed:
        w("\n## Service / Version Changes\n")
        for ip, port, a, b in d.service_changed:
            w(f"- `{ip}:{port}`: {a} -> **{b}**")

    if d.hosts_added:
        w("\n## New Hosts\n")
        for ip in d.hosts_added:
            w(f"- `{ip}`")
    if d.hosts_removed:
        w("\n## Removed Hosts\n")
        for ip in d.hosts_removed:
            w(f"- `{ip}`")
    if d.host_status_changed:
        w("\n## Host Status Changes\n")
        for ip, a, b in d.host_status_changed:
            w(f"- `{ip}`: {a} -> {b}")

    if d.http_added:
        w("\n## New HTTP/HTTPS Services\n")
        for url in d.http_added:
            w(f"- {url}")
    if d.http_removed:
        w("\n## Removed HTTP/HTTPS Services\n")
        for url in d.http_removed:
            w(f"- {url}")

    if d.findings_new:
        w("\n## [+] New Findings\n")
        w("| Severity | Asset | Finding | Validation | Source |")
        w("|---|---|---|---|---|")
        for f in d.findings_new:
            w(f"| {f['severity']} | {f['asset']} | {f['title']} | "
              f"{f['validation']} | {f['source']} |")
    if d.findings_resolved:
        w("\n## [resolved] Resolved Findings\n")
        w("| Severity | Asset | Finding |")
        w("|---|---|---|")
        for f in d.findings_resolved:
            w(f"| {f['severity']} | {f['asset']} | {f['title']} |")

    return "\n".join(s) + "\n"


def write_diff(d: DiffResult, out_dir: str) -> dict:
    os.makedirs(out_dir, exist_ok=True)
    md_path = os.path.join(out_dir, "diff.md")
    json_path = os.path.join(out_dir, "diff.json")
    with open(md_path, "w", encoding="utf-8") as fh:
        fh.write(render_markdown(d))
    with open(json_path, "w", encoding="utf-8") as fh:
        json.dump(d.to_dict(), fh, indent=2)
    return {"markdown": md_path, "json": json_path}

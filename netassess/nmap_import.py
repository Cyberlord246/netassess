"""Import an existing nmap scan so its open ports feed netassess directly.

Supports nmap XML (`-oX`) and greppable (`-oG`) output. Returns a mapping of
IP -> list of open-port dicts {port, service, product, version}. The caller adds
these IPs to scope (the operator supplying an nmap file asserts authorization,
exactly like listing them in --targets) and seeds them as already-open, skipping
netassess's own port scan.
"""
from __future__ import annotations

import re
import xml.etree.ElementTree as ET


def parse(path: str) -> dict[str, list[dict]]:
    with open(path, "r", encoding="utf-8", errors="replace") as fh:
        head = fh.read(4096)
        fh.seek(0)
        data = fh.read()
    if "<nmaprun" in head or path.lower().endswith((".xml",)):
        try:
            return _parse_xml(data)
        except ET.ParseError:
            pass  # fall through to greppable
    return _parse_greppable(data)


def _parse_xml(data: str) -> dict[str, list[dict]]:
    out: dict[str, list[dict]] = {}
    root = ET.fromstring(data)
    for host in root.findall("host"):
        # prefer IPv4/IPv6 address; skip MAC
        ip = ""
        for addr in host.findall("address"):
            if addr.get("addrtype") in ("ipv4", "ipv6"):
                ip = addr.get("addr", "")
                break
        if not ip:
            continue
        ports = []
        for p in host.findall("./ports/port"):
            st = p.find("state")
            if st is None or st.get("state") != "open":
                continue
            if p.get("protocol", "tcp") != "tcp":
                continue
            svc = p.find("service")
            ports.append({
                "port": int(p.get("portid")),
                "service": (svc.get("name") if svc is not None else "") or "",
                "product": (svc.get("product") if svc is not None else "") or "",
                "version": (svc.get("version") if svc is not None else "") or "",
            })
        if ports:
            out[ip] = ports
    return out


_GNMAP_HOST = re.compile(r"^Host:\s+(\S+).*?\bPorts:\s+(.*)$")


def _parse_greppable(data: str) -> dict[str, list[dict]]:
    out: dict[str, list[dict]] = {}
    for line in data.splitlines():
        m = _GNMAP_HOST.match(line.strip())
        if not m:
            continue
        ip, portblob = m.group(1), m.group(2)
        ports = []
        # each: port/state/proto/owner/service/rpc/version/
        for entry in portblob.split(","):
            fields = entry.strip().split("/")
            if len(fields) < 3:
                continue
            if fields[1] != "open" or fields[2] != "tcp":
                continue
            try:
                num = int(fields[0])
            except ValueError:
                continue
            ports.append({
                "port": num,
                "service": fields[4] if len(fields) > 4 else "",
                "product": "",
                "version": fields[6] if len(fields) > 6 else "",
            })
        if ports:
            out[ip] = ports
    return out

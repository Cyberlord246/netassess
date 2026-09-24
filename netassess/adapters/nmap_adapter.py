"""Optional Nmap adapter.

Used only when nmap is present on PATH. It parses nmap's XML output into the
platform's Port/Service models. If nmap is absent, ``available()`` returns
False and the engine falls back to the pure-Python scanner.

IMPORTANT: this adapter is a *consumer* of the Scope Engine, not a bypass. The
caller must authorize each target before invoking scan(); we additionally pass
only already-authorized targets to nmap and use non-aggressive defaults.
"""
from __future__ import annotations

import xml.etree.ElementTree as ET
from typing import Optional

from ..models import Confidence, Port, PortState, Service
from .base import ToolAdapter
from .process import ProcResult, run, which


class NmapAdapter(ToolAdapter):
    name = "nmap"

    def available(self) -> bool:
        return which("nmap") is not None

    def scan(self, ip: str, ports: list[int], timeout: float = 120.0,
             service_detection: str = "banner", min_rate: Optional[int] = None
             ) -> tuple[list[Port], ProcResult]:
        """Run a single-host nmap TCP connect scan, return parsed ports."""
        port_spec = ",".join(str(p) for p in ports) if ports else "1-1000"
        argv = [
            "nmap",
            "-sT",              # TCP connect (no raw sockets / privileges needed)
            "-Pn",              # host already validated live by our discovery
            "-n",               # no nmap DNS (we do reverse DNS ourselves)
            "-p", port_spec,
            "--open",
            "-oX", "-",         # XML to stdout
        ]
        if service_detection == "banner":
            argv.append("-sV")
            argv += ["--version-intensity", "2"]
        elif service_detection == "deep":
            argv.append("-sV")
            argv += ["--version-intensity", "5"]
        if min_rate:
            argv += ["--min-rate", str(min_rate)]
        argv.append(ip)

        res = run(argv, timeout=timeout)
        if not res.ok or not res.stdout.strip():
            return [], res
        try:
            return self._parse_xml(res.stdout), res
        except ET.ParseError as exc:
            res.error = f"xml parse error: {exc}"
            return [], res

    def _parse_xml(self, xml_text: str) -> list[Port]:
        root = ET.fromstring(xml_text)
        ports: list[Port] = []
        for host in root.findall("host"):
            for port_el in host.findall("./ports/port"):
                state_el = port_el.find("state")
                if state_el is None or state_el.get("state") != "open":
                    continue
                num = int(port_el.get("portid", "0"))
                proto = port_el.get("protocol", "tcp")
                svc_el = port_el.find("service")
                service = Service(protocol=proto)
                if svc_el is not None:
                    service.name = svc_el.get("name", "unknown")
                    service.product = svc_el.get("product", "")
                    service.version = svc_el.get("version", "")
                    conf = svc_el.get("conf", "0")
                    service.confidence = (
                        Confidence.HIGH if conf and int(conf) >= 8
                        else Confidence.MEDIUM if conf and int(conf) >= 5
                        else Confidence.LOW
                    )
                    extra = svc_el.get("extrainfo", "")
                    if extra:
                        service.evidence = extra
                ports.append(Port(number=num, protocol=proto,
                                  state=PortState.OPEN, service=service))
        return ports

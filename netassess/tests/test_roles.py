"""Tests for asset-role classification + anomaly detection.

Run: python -m netassess.tests.test_roles
"""
from __future__ import annotations

from ..models import Host, Port, PortState, Service
from ..roles import classify, detect_anomalies


def _host(ports, udp=None):
    h = Host(ip="192.0.2.10")
    for num, name in ports.items():
        h.ports[num] = Port(num, state=PortState.OPEN, service=Service(name=name))
    for num, name in (udp or {}).items():
        h.udp_ports[num] = Port(num, protocol="udp", state=PortState.OPEN,
                                service=Service(name=name, protocol="udp"))
    return h


def test_classify_web_server():
    rr = classify(_host({80: "http", 443: "https"}))
    assert rr.primary == "web-server"


def test_classify_database():
    rr = classify(_host({3306: "mysql"}))
    assert rr.primary == "database"


def test_classify_domain_controller():
    # Kerberos + LDAP + SMB => domain-controller (supersedes 'directory')
    rr = classify(_host({88: "kerberos", 389: "ldap", 445: "smb", 53: "dns"}))
    assert rr.primary == "domain-controller"
    assert "directory" not in rr.roles


def test_classify_unknown_when_no_ports():
    assert classify(Host(ip="192.0.2.10")).primary == "unknown"


def test_anomaly_db_with_web():
    h = _host({80: "http", 443: "https", 3306: "mysql"})
    rr = classify(h)
    titles = {f.title for f in detect_anomalies(h, rr)}
    assert "Database co-located with web service" in titles


def test_anomaly_consolidation():
    # web + database + mail => 3 critical roles
    h = _host({80: "http", 3306: "mysql", 25: "smtp", 143: "imap"})
    rr = classify(h)
    titles = {f.title for f in detect_anomalies(h, rr)}
    assert "Multiple critical roles consolidated on one host" in titles


def test_anomaly_mgmt_plane_high():
    h = _host({2375: "docker"})
    rr = classify(h)
    fs = detect_anomalies(h, rr)
    mgmt = [f for f in fs if f.title == "Infrastructure management interface reachable"]
    assert mgmt and mgmt[0].severity.value == "high"


def test_anomaly_dc_extra_roles():
    h = _host({88: "kerberos", 389: "ldap", 445: "smb", 80: "http", 3306: "mysql"})
    rr = classify(h)
    titles = {f.title for f in detect_anomalies(h, rr)}
    assert "Domain Controller running non-DC services" in titles


def test_no_anomaly_for_plain_web():
    h = _host({80: "http", 443: "https"})
    rr = classify(h)
    assert detect_anomalies(h, rr) == []


def _run_all():
    fns = [v for k, v in globals().items() if k.startswith("test_")]
    for fn in fns:
        fn()
        print(f"  ok  {fn.__name__}")
    print(f"\n{len(fns)}/{len(fns)} tests passed")


if __name__ == "__main__":
    _run_all()

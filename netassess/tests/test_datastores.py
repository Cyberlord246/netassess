"""Deep unauthenticated datastore checks (Mongo/Memcached/Elasticsearch/CouchDB).

Run: python -m netassess.tests.test_datastores
"""
from __future__ import annotations

import struct

from ..config import Config
from ..models import Host, Port, PortState, Service, Severity, ValidationState
from ..probers import DatabaseProbe
from ..probers import service_probes as sp
from ..scope import ScopeEngine


def _probe():
    cfg = Config(targets=["10.0.0.9"])
    return DatabaseProbe(cfg, ScopeEngine(cfg))


def _port(num):
    return Port(number=num, state=PortState.OPEN, service=Service(name=""))


def test_mongo_listdb_query_is_op_query():
    pkt = sp._mongo_listdb_query()
    assert struct.unpack("<i", pkt[:4])[0] == len(pkt)       # messageLength
    assert struct.unpack("<i", pkt[12:16])[0] == 2004        # OP_QUERY opcode
    assert b"admin.$cmd\x00" in pkt and b"listDatabases" in pkt


def test_mongo_unauth_flagged(monkeypatch=None):
    pr = _probe()
    orig = sp._recv_banner
    sp._recv_banner = lambda *a, **k: (b"\x00\x00...databases\x00local\x00admin", "")
    try:
        res = pr.probe(Host(ip="10.0.0.9"), _port(27017))
    finally:
        sp._recv_banner = orig
    f = res.findings[0]
    assert f.severity == Severity.HIGH and "MongoDB" in f.title
    assert f.validation == ValidationState.CONFIRMED


def test_mongo_auth_required_is_exposure_only():
    pr = _probe()
    orig = sp._recv_banner
    sp._recv_banner = lambda *a, **k: (b'{"errmsg":"command listDatabases requires authentication"}', "")
    try:
        res = pr.probe(Host(ip="10.0.0.9"), _port(27017))
    finally:
        sp._recv_banner = orig
    f = res.findings[0]
    assert f.severity == Severity.MEDIUM and "exposed" in f.title.lower()


def test_memcached_stats_unauth():
    pr = _probe()
    orig = sp._recv_banner
    sp._recv_banner = lambda *a, **k: (
        b"STAT version 1.6.9\r\nSTAT curr_items 42\r\nEND\r\n", "")
    try:
        res = pr.probe(Host(ip="10.0.0.9"), _port(11211))
    finally:
        sp._recv_banner = orig
    f = res.findings[0]
    assert f.severity == Severity.HIGH and "Memcached" in f.title
    assert "1.6.9" in f.evidence


def test_elasticsearch_open_indices():
    pr = _probe()
    import netassess.webfetch as wf
    orig = wf.fetch
    wf.fetch = lambda *a, **k: (200, {}, "health status index docs.count\ngreen open idx1 10")
    try:
        res = pr.probe(Host(ip="10.0.0.9"), _port(9200))
    finally:
        wf.fetch = orig
    f = res.findings[0]
    assert f.severity == Severity.HIGH and "elasticsearch" in f.title.lower()


def test_couchdb_alldbs_but_auth_required():
    pr = _probe()
    import netassess.webfetch as wf
    orig = wf.fetch
    wf.fetch = lambda *a, **k: (401, {}, "")
    try:
        res = pr.probe(Host(ip="10.0.0.9"), _port(5984))
    finally:
        wf.fetch = orig
    f = res.findings[0]
    assert f.severity == Severity.MEDIUM and "exposed" in f.title.lower()


def _run_all():
    fns = [v for k, v in globals().items() if k.startswith("test_")]
    for fn in fns:
        fn()
        print(f"  ok  {fn.__name__}")
    print(f"\n{len(fns)}/{len(fns)} tests passed")


if __name__ == "__main__":
    _run_all()

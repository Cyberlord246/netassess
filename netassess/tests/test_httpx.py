"""Tests for the httpx adapter + engine bulk-probe integration (no binary needed).

Run: python -m netassess.tests.test_httpx
"""
from __future__ import annotations

import json

from ..adapters.httpx_adapter import HttpxAdapter
from ..adapters.process import ProcResult
from ..config import Config
from ..engine import AssessmentEngine
from ..models import HostStatus, Port, PortState, Service


_REC = {
    "input": "203.0.113.5:443", "url": "https://203.0.113.5:443", "scheme": "https",
    "port": "443", "status_code": 200, "title": "Acme", "webserver": "nginx/1.18.0",
    "content_type": "text/html; charset=utf-8", "content_length": 5120,
    "tech": ["Nginx", "PHP"], "cdn_name": "cloudflare",
    "tls": {"subject_cn": "acme.example.com", "issuer_cn": "R3",
            "subject_an": ["acme.example.com", "www.acme.example.com"],
            "tls_version": "tls13", "cipher": "TLS_AES_256_GCM_SHA384"},
}


def test_build_argv_core_flags():
    argv = HttpxAdapter().build_argv(timeout=7, threads=40, rate=100)
    for f in ("-json", "-silent", "-tls-grab", "-tech-detect", "-status-code"):
        assert f in argv
    assert "-rate-limit" in argv and "100" in argv


def test_parse_json_filters_noise():
    a = HttpxAdapter()
    out = a.parse_json(json.dumps(_REC) + "\nnot json\n{bad\n")
    assert len(out) == 1 and out[0]["status_code"] == 200


def test_to_http_service_maps_fields():
    svc = HttpxAdapter().to_http_service(_REC, "203.0.113.5", 443)
    assert svc.scheme == "https" and svc.status == 200
    assert svc.server == "nginx/1.18.0"
    assert svc.content_type == "text/html"
    assert [t.name for t in svc.technologies] == ["Nginx", "PHP"]
    assert svc.tls and svc.tls.sans == ["acme.example.com", "www.acme.example.com"]


class _FakeHttpx(HttpxAdapter):
    """httpx adapter that returns canned records without the binary."""
    def available(self):
        return True

    def probe(self, targets, **kw):
        rec = dict(_REC)
        rec["input"] = targets[0]      # echo the target we were given
        rec["url"] = f"http://{targets[0]}"
        rec["scheme"] = "http"
        return [rec], ProcResult(ok=True, returncode=0, stdout="{}", stderr="")


def test_engine_bulk_populates_service_and_drops_httpprobe():
    cfg = Config(targets=["127.0.0.1"], ports=[8080], skip_discovery=True,
                 http_tool="builtin")          # real adapter off; we inject a fake
    eng = AssessmentEngine(cfg, log=lambda *a, **k: None)
    eng.httpx = _FakeHttpx()
    h = eng.graph.get_or_create("127.0.0.1")
    h.status = HostStatus.LIVE
    h.ports[8080] = Port(number=8080, state=PortState.OPEN, service=Service(name="http-alt"))

    confirmed = eng._run_httpx_bulk()
    assert ("127.0.0.1", 8080) in confirmed
    svcs = [s for _hh, s in eng.graph.all_http_services()]
    assert any(s.port == 8080 and s.status == 200 for s in svcs)   # populated by httpx
    assert h.ports[8080].service.name == "http"                    # identity stamped


def _run_all():
    fns = [v for k, v in sorted(globals().items()) if k.startswith("test_")]
    for fn in fns:
        fn()
        print(f"  ok  {fn.__name__}")
    print(f"\n{len(fns)}/{len(fns)} tests passed")


if __name__ == "__main__":
    _run_all()

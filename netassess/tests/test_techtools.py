"""Tests for external tech fingerprinting (whatweb/wappalyzer) + tech-aware
content-discovery extensions.

Run: python -m netassess.tests.test_techtools
"""
from __future__ import annotations

import json

from ..adapters.techtools import WhatWebAdapter, WappalyzerAdapter, choose
from ..models import HTTPService, Technology
from ..techdetect import extensions_for_service

_WHATWEB = json.dumps([{
    "target": "http://10.0.0.5/",
    "http_status": 200,
    "plugins": {
        "nginx": {"version": ["1.18.0"]},
        "PHP": {"version": ["8.1.2"]},
        "WordPress": {"version": ["6.2"]},
        "Country": {"string": ["RESERVED"]},     # meta -> skipped
        "Title": {"string": ["Home"]},            # meta -> skipped
    },
}])


def test_whatweb_parse_skips_meta_and_keeps_versions():
    res = WhatWebAdapter().parse_json(_WHATWEB)
    techs = {t.name: t.version for t in res["http://10.0.0.5/"]}
    assert "nginx" in techs and techs["nginx"] == "1.18.0"
    assert techs["PHP"] == "8.1.2" and "WordPress" in techs
    assert "Country" not in techs and "Title" not in techs


def test_whatweb_handles_ndjson():
    ndjson = "\n".join(json.dumps(o) for o in json.loads(_WHATWEB))
    res = WhatWebAdapter().parse_json(ndjson)
    assert res and "http://10.0.0.5/" in res


def test_wappalyzer_parse():
    doc = json.dumps({"urls": {"http://h/": {}}, "technologies": [
        {"name": "Nginx", "version": "1.20", "categories": [{"name": "Web servers"}]},
        {"name": "React", "version": "", "categories": [{"name": "JS frameworks"}]},
    ]})
    res = WappalyzerAdapter().parse_json(doc, url="http://h/")
    names = {t.name for t in res["http://h/"]}
    assert names == {"Nginx", "React"}


def test_choose_modes():
    assert choose("builtin") == (None, "")
    adapter, name = choose("whatweb")
    assert name == "whatweb"
    adapter, name = choose("wappalyzer")
    assert name == "wappalyzer"


def test_extensions_from_detected_tech():
    svc = HTTPService(url="http://h/", ip="h", port=80, scheme="http")
    svc.technologies = [Technology(name="PHP", category="language")]
    assert "php" in extensions_for_service(svc)

    svc2 = HTTPService(url="http://h/", ip="h", port=80, scheme="http",
                       server="Microsoft-IIS/10.0")
    assert "aspx" in extensions_for_service(svc2)

    svc3 = HTTPService(url="http://h/", ip="h", port=80, scheme="http")
    svc3.technologies = [Technology(name="Apache Tomcat", category="app-server")]
    assert "jsp" in extensions_for_service(svc3)

    # nothing identifiable -> no extensions
    svc4 = HTTPService(url="http://h/", ip="h", port=80, scheme="http")
    assert extensions_for_service(svc4) == []


def test_ferox_extensions_tech_user_and_basic_fallback():
    from ..config import Config
    from ..engine import AssessmentEngine
    from ..models import Port, PortState, Service

    def _svc(ip="10.0.0.5", techs=()):
        s = HTTPService(url=f"http://{ip}/", ip=ip, port=80, scheme="http")
        s.technologies = [Technology(name=t, category="") for t in techs]
        return s

    # tech identified -> tech extensions merged with the user's
    eng = AssessmentEngine(Config(targets=["10.0.0.5"], content_extensions="bak",
                                  show_progress=False))
    out = eng._ferox_extensions(_svc(techs=["PHP"])).split(",")
    assert "bak" in out and "php" in out

    # no tech, explicit user set -> exactly the user's
    assert eng._ferox_extensions(_svc()).split(",") == ["bak"]

    # no tech and no user set -> basic fallback
    eng2 = AssessmentEngine(Config(targets=["10.0.0.5"], show_progress=False))
    from ..techdetect import BASIC_EXTENSIONS
    assert eng2._ferox_extensions(_svc()).split(",") == BASIC_EXTENSIONS


def _run_all():
    fns = [v for k, v in globals().items() if k.startswith("test_")]
    for fn in fns:
        fn()
        print(f"  ok  {fn.__name__}")
    print(f"\n{len(fns)}/{len(fns)} tests passed")


if __name__ == "__main__":
    _run_all()

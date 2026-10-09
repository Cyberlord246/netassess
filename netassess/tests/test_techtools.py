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


def _run_all():
    fns = [v for k, v in globals().items() if k.startswith("test_")]
    for fn in fns:
        fn()
        print(f"  ok  {fn.__name__}")
    print(f"\n{len(fns)}/{len(fns)} tests passed")


if __name__ == "__main__":
    _run_all()

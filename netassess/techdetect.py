"""Lightweight technology fingerprinting for HTTP services.

Signature-based, evidence-carrying, and honest about confidence. We never assert
a version we did not observe. Signals come from response headers, cookies, and
small body markers (meta generator tags, well-known paths in HTML).
"""
from __future__ import annotations

import re

from .models import Confidence, HTTPService, Technology


# (name, category, header/cookie/body signal). Each tuple is a matcher.
# matcher kinds: ("header", name, regex), ("cookie", regex), ("body", regex),
#                ("server", regex)
_SIGS = [
    ("nginx", "web-server", ("server", r"nginx")),
    ("Apache httpd", "web-server", ("server", r"apache")),
    ("Microsoft IIS", "web-server", ("server", r"microsoft-iis")),
    ("LiteSpeed", "web-server", ("server", r"litespeed")),
    ("Caddy", "web-server", ("server", r"caddy")),
    ("Cloudflare", "cdn", ("header", "cf-ray", r".+")),
    ("Cloudflare", "cdn", ("server", r"cloudflare")),
    ("Amazon CloudFront", "cdn", ("header", "x-amz-cf-id", r".+")),
    ("Fastly", "cdn", ("header", "x-served-by", r"cache-.*")),
    ("Varnish", "cache", ("header", "via", r"varnish")),
    ("PHP", "language", ("header", "x-powered-by", r"php")),
    ("PHP", "language", ("cookie", r"phpsessid")),
    ("ASP.NET", "framework", ("header", "x-powered-by", r"asp\.net")),
    ("ASP.NET", "framework", ("cookie", r"asp\.net_sessionid")),
    ("Express", "framework", ("header", "x-powered-by", r"express")),
    ("Java (Servlet)", "language", ("cookie", r"jsessionid")),
    ("Ruby on Rails", "framework", ("cookie", r"_session_id|_rails")),
    ("Django", "framework", ("cookie", r"csrftoken|sessionid")),
    ("Laravel", "framework", ("cookie", r"laravel_session")),
    ("WordPress", "cms", ("body", r"/wp-content/|/wp-includes/")),
    ("WordPress", "cms", ("body", r'name="generator" content="WordPress')),
    ("Drupal", "cms", ("header", "x-generator", r"drupal")),
    ("Drupal", "cms", ("body", r"Drupal.settings|/sites/default/files")),
    ("Joomla", "cms", ("body", r"/media/jui/|Joomla!")),
    ("Kibana", "app", ("body", r"kbn-|kibana")),
    ("Grafana", "app", ("body", r"grafana")),
    ("Jenkins", "app", ("header", "x-jenkins", r".+")),
    ("Elasticsearch", "datastore", ("body", r'"cluster_name"|"lucene_version"')),
    ("Tomcat", "app-server", ("server", r"tomcat|coyote")),
    ("Jetty", "app-server", ("server", r"jetty")),
    ("Gunicorn", "app-server", ("server", r"gunicorn")),
    ("OpenResty", "web-server", ("server", r"openresty")),
    ("Traefik", "reverse-proxy", ("header", "x-traefik", r".+")),
    ("HAProxy", "load-balancer", ("header", "x-haproxy-server-state", r".+")),
    ("Kubernetes Ingress", "infra", ("header", "x-kubernetes", r".+")),
]

_VERSION_HEADER_RE = {
    "nginx": re.compile(r"nginx/([\d.]+)", re.I),
    "Apache httpd": re.compile(r"apache/([\d.]+)", re.I),
    "Microsoft IIS": re.compile(r"microsoft-iis/([\d.]+)", re.I),
    "PHP": re.compile(r"php/([\d.]+)", re.I),
    "OpenResty": re.compile(r"openresty/([\d.]+)", re.I),
}


def detect_technologies(svc: HTTPService) -> list[Technology]:
    headers = {k.lower(): (v or "") for k, v in svc.headers.items()}
    server = headers.get("server", "")
    powered = headers.get("x-powered-by", "")
    setcookie = headers.get("set-cookie", "")
    body = ""  # body not stored on svc; header+cookie signals only here
    found: dict[str, Technology] = {}

    def add(name, category, evidence, conf=Confidence.MEDIUM):
        if name in found:
            return
        tech = Technology(name=name, category=category, evidence=evidence,
                          confidence=conf)
        # version extraction from server/x-powered-by
        combined = f"{server} {powered}"
        vr = _VERSION_HEADER_RE.get(name)
        if vr:
            m = vr.search(combined)
            if m:
                tech.version = m.group(1)
                tech.confidence = Confidence.HIGH
        found[name] = tech

    for name, category, matcher in _SIGS:
        kind = matcher[0]
        if kind == "server" and re.search(matcher[1], server, re.I):
            add(name, category, f"Server: {server}", Confidence.HIGH)
        elif kind == "header":
            hv = headers.get(matcher[1], "")
            if hv and re.search(matcher[2], hv, re.I):
                add(name, category, f"{matcher[1]}: {hv}", Confidence.HIGH)
        elif kind == "cookie" and re.search(matcher[1], setcookie, re.I):
            add(name, category, "cookie signature", Confidence.MEDIUM)
        elif kind == "body" and body and re.search(matcher[1], body, re.I):
            add(name, category, "body signature", Confidence.MEDIUM)

    return list(found.values())

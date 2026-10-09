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
    # modern front-end frameworks / SPAs (body markers — the common case today)
    ("React", "framework", ("body", r"__REACT_DEVTOOLS|data-reactroot|/static/js/main\.")),
    ("Angular", "framework", ("body", r"ng-version=|ng-app|zone\.js")),
    ("Vue.js", "framework", ("body", r"data-v-[0-9a-f]{8}|__VUE__")),
    ("Next.js", "framework", ("body", r"/_next/|__NEXT_DATA__")),
    ("Nuxt.js", "framework", ("body", r"__NUXT__|/_nuxt/")),
    ("jQuery", "library", ("body", r"jquery(?:[.-][\d.]+)?(?:\.min)?\.js")),
    ("Bootstrap", "library", ("body", r"bootstrap(?:[.-][\d.]+)?(?:\.min)?\.(?:css|js)")),
    ("WordPress", "cms", ("header", "link", r"wp-json")),
    ("Shopify", "ecommerce", ("body", r"cdn\.shopify\.com|Shopify\.")),
    ("Magento", "ecommerce", ("body", r"/static/version\d|Mage\.|magento")),
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


# technology/language -> file extensions worth probing in content discovery.
# Keyed by a lowercase substring matched against tech names, server, x-powered-by.
_TECH_EXT = [
    ("php", ["php", "phtml", "php5", "php7", "inc"]),
    ("wordpress", ["php"]),
    ("drupal", ["php"]),
    ("joomla", ["php"]),
    ("laravel", ["php"]),
    ("asp.net", ["aspx", "asp", "ashx", "asmx", "axd"]),
    ("iis", ["aspx", "asp", "ashx"]),
    ("servlet", ["jsp", "jspx", "do", "action"]),
    ("tomcat", ["jsp", "jspx", "do", "action"]),
    ("jetty", ["jsp"]),
    ("coldfusion", ["cfm", "cfc"]),
    ("express", ["js", "json"]),
    ("node", ["js", "json"]),
    ("django", ["py"]),
    ("flask", ["py"]),
    ("ruby on rails", ["rb", "erb", "json"]),
    ("perl", ["pl", "cgi"]),
]


def extensions_for_service(svc: HTTPService) -> list[str]:
    """Extensions to probe for this service, derived from its identified
    technologies/server/language. Empty when nothing identifiable."""
    hay = " ".join([
        (svc.server or ""),
        (svc.headers.get("x-powered-by", "") if svc.headers else ""),
        " ".join(t.name for t in (svc.technologies or [])),
    ]).lower()
    out: list[str] = []
    for key, exts in _TECH_EXT:
        if key in hay:
            for e in exts:
                if e not in out:
                    out.append(e)
    return out


def detect_technologies(svc: HTTPService, body: str = "") -> list[Technology]:
    headers = {k.lower(): (v or "") for k, v in svc.headers.items()}
    server = headers.get("server", "")
    powered = headers.get("x-powered-by", "")
    setcookie = headers.get("set-cookie", "")
    body = body or ""          # response body enables CMS/SPA/library detection
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

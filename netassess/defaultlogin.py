"""Default-login exposure checks.

Conservative and non-destructive: this does **not** attempt any login and never
submits credentials (that would be a credential attack). Instead, *only where a
product/technology with well-known default credentials has been identified*, it
GETs that product's known login/admin path and, if the interface is reachable,
flags it for manual verification that defaults were changed.

This keeps the check scoped to identified services (no indiscriminate probing of
every host) and avoids any brute forcing. nuclei's `default-login` templates can
still actively test where that is permitted; this gives a built-in, credential-
free signal without nuclei.
"""
from __future__ import annotations

from urllib.parse import urlparse

from .models import Confidence, Finding, Severity, ValidationState
from .webfetch import fetch

# product keyword (matched against tech names / server / service name / title)
# -> (login-or-admin path, human label, default-credential note)
KNOWN: dict[str, tuple[str, str, str]] = {
    "grafana":    ("/login", "Grafana", "ships admin/admin"),
    "jenkins":    ("/login", "Jenkins", "console is often unauthenticated"),
    "tomcat":     ("/manager/html", "Apache Tomcat Manager", "tomcat/tomcat, admin/admin"),
    "phpmyadmin": ("/index.php", "phpMyAdmin", "root with empty/weak password"),
    "kibana":     ("/app/kibana", "Kibana", "elastic/changeme"),
    "wordpress":  ("/wp-login.php", "WordPress", "weak/default admin password"),
    "gitlab":     ("/users/sign_in", "GitLab", "root with initial/weak password"),
    "jira":       ("/login.jsp", "Jira", "admin/admin"),
    "portainer":  ("/", "Portainer", "admin set on first use — often weak"),
    "rabbitmq":   ("/", "RabbitMQ Management", "guest/guest"),
    "adminer":    ("/", "Adminer", "database default credentials"),
    "solr":       ("/solr/", "Apache Solr admin", "frequently unauthenticated"),
    "jupyter":    ("/tree", "Jupyter", "token-less / weak token"),
    "pgadmin":    ("/login", "pgAdmin", "default admin email/password"),
}


class DefaultLoginChecker:
    def __init__(self, config, scope):
        self.config = config
        self.scope = scope
        self.timeout = float(getattr(config, "timeout", 5.0)) + 2.0

    def _haystack(self, host, svc) -> str:
        parts = [svc.server or "", svc.title or ""]
        parts += [t.name for t in (svc.technologies or [])]
        p = host.ports.get(svc.port)
        if p is not None:
            parts.append(p.service.name or "")
            parts.append(getattr(p.service, "product", "") or "")
        return " ".join(parts).lower()

    def check_service(self, host, svc) -> list[Finding]:
        if not self.scope.authorize(svc.ip, svc.port).allowed:
            return []
        hay = self._haystack(host, svc)
        findings: list[Finding] = []
        seen_paths: set[str] = set()
        host_header = None
        parsed = urlparse(svc.url)
        if parsed.hostname and parsed.hostname != svc.ip:
            host_header = parsed.hostname
        for key, (path, label, note) in KNOWN.items():
            if key not in hay or path in seen_paths:
                continue
            status, _headers, _body = fetch(svc.ip, svc.port, svc.scheme, path,
                                            host_header=host_header,
                                            timeout=self.timeout)
            if status is None:
                continue
            seen_paths.add(path)
            if status in (200, 401, 403):
                reachable = "reachable" if status == 200 else \
                    f"present but protected (HTTP {status})"
                findings.append(Finding(
                    title=f"Exposed {label} login interface (default-credential risk)",
                    asset=f"{svc.ip}:{svc.port}",
                    evidence=f"{svc.scheme}://{svc.ip}:{svc.port}{path} -> HTTP "
                             f"{status} ({reachable}); {label} {note}. No "
                             f"credentials were submitted.",
                    description=f"A {label} login/admin interface is exposed. "
                                f"{label} is known to ship or commonly run with "
                                f"default credentials ({note}).",
                    why_it_matters="If default credentials remain, this is a "
                                   "direct account-takeover / full-compromise "
                                   "path.",
                    severity=Severity.MEDIUM, confidence=Confidence.MEDIUM,
                    impact="Possible authenticated access with known defaults.",
                    remediation="Verify default credentials have been changed; "
                                "restrict the interface to trusted networks / "
                                "VPN; enable MFA where supported.",
                    validation=ValidationState.NEEDS_VALIDATION,
                    source="default-login", category="default-login",
                ))
        return findings

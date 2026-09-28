"""Content discovery — safe enumeration of common web paths.

For each discovered HTTP/HTTPS service, this requests a *curated, bounded* list
of well-known paths (admin panels, auth pages, API docs, exposed config/secrets,
status/debug endpoints) to map the reachable attack surface.

Safety properties (this is assessment, not exploitation):
  * GET requests only — never posts, never submits forms, never authenticates.
  * Every request passes through the Scope Engine and its rate/concurrency gate.
  * A fixed, modest wordlist (no large-scale fuzzing).
  * Soft-404 calibration: servers that answer 200 to everything are detected so
    we don't report phantom hits.
  * Read-only: it reports what *exists*; it does not act on what it finds.

Enable with ``--content-discovery`` (off by default because it is more active
than passive probing).
"""
from __future__ import annotations

import http.client
import os
import random
import re
import socket
import ssl
import string
import threading
import time
from queue import Empty, Queue

from .config import Config
from .models import (
    Confidence, Finding, HTTPService, Host, Severity, ValidationState,
)
from .scope import ScopeEngine

_TITLE_RE = re.compile(r"<title[^>]*>(.*?)</title>", re.I | re.S)
_MAX_BODY = 16384

# Status codes that indicate a path is present/interesting.
_PRESENT = {200, 201, 204, 301, 302, 307, 308, 401, 403, 405, 500}

# Curated path list. (path, category, base_severity_if_found)
# Severities: secrets/backup = high, admin/api/debug = medium, info files = info.
_PATHS: list[tuple[str, str, Severity]] = [
    # --- authentication / admin surfaces ---
    ("admin", "admin", Severity.MEDIUM),
    ("admin/", "admin", Severity.MEDIUM),
    ("administrator", "admin", Severity.MEDIUM),
    ("admin/login", "admin", Severity.MEDIUM),
    ("login", "auth", Severity.MEDIUM),
    ("signin", "auth", Severity.MEDIUM),
    ("signup", "auth", Severity.MEDIUM),
    ("register", "auth", Severity.MEDIUM),
    ("user/login", "auth", Severity.MEDIUM),
    ("account/login", "auth", Severity.MEDIUM),
    ("dashboard", "admin", Severity.MEDIUM),
    ("console", "admin", Severity.MEDIUM),
    ("manage", "admin", Severity.MEDIUM),
    ("management", "admin", Severity.MEDIUM),
    ("cpanel", "admin", Severity.MEDIUM),
    ("wp-admin/", "admin", Severity.MEDIUM),
    ("wp-login.php", "auth", Severity.MEDIUM),
    ("phpmyadmin/", "admin", Severity.HIGH),
    ("adminer.php", "admin", Severity.HIGH),
    # --- API surfaces ---
    ("api", "api", Severity.MEDIUM),
    ("api/", "api", Severity.MEDIUM),
    ("api/v1", "api", Severity.MEDIUM),
    ("api/v2", "api", Severity.MEDIUM),
    ("graphql", "api", Severity.MEDIUM),
    ("rest", "api", Severity.MEDIUM),
    ("swagger", "api-docs", Severity.MEDIUM),
    ("swagger-ui.html", "api-docs", Severity.MEDIUM),
    ("swagger/index.html", "api-docs", Severity.MEDIUM),
    ("swagger.json", "api-docs", Severity.MEDIUM),
    ("openapi.json", "api-docs", Severity.MEDIUM),
    ("api-docs", "api-docs", Severity.MEDIUM),
    ("v2/api-docs", "api-docs", Severity.MEDIUM),
    # --- exposed config / secrets (high value) ---
    (".env", "secrets", Severity.HIGH),
    (".git/config", "secrets", Severity.HIGH),
    (".git/HEAD", "secrets", Severity.HIGH),
    (".svn/entries", "secrets", Severity.HIGH),
    ("config.php", "config", Severity.HIGH),
    ("config.json", "config", Severity.HIGH),
    ("wp-config.php", "config", Severity.HIGH),
    ("wp-config.php.bak", "config", Severity.HIGH),
    ("web.config", "config", Severity.HIGH),
    (".htaccess", "config", Severity.MEDIUM),
    ("backup.zip", "backup", Severity.HIGH),
    ("backup.sql", "backup", Severity.HIGH),
    ("db.sql", "backup", Severity.HIGH),
    ("dump.sql", "backup", Severity.HIGH),
    ("database.sql", "backup", Severity.HIGH),
    ("id_rsa", "secrets", Severity.HIGH),
    ("credentials.json", "secrets", Severity.HIGH),
    ("secrets.json", "secrets", Severity.HIGH),
    (".DS_Store", "info-leak", Severity.LOW),
    # --- status / debug / info endpoints ---
    ("server-status", "debug", Severity.MEDIUM),
    ("status", "debug", Severity.LOW),
    ("health", "debug", Severity.INFO),
    ("healthz", "debug", Severity.INFO),
    ("metrics", "debug", Severity.MEDIUM),
    ("actuator", "debug", Severity.MEDIUM),
    ("actuator/health", "debug", Severity.LOW),
    ("actuator/env", "debug", Severity.HIGH),
    ("debug", "debug", Severity.MEDIUM),
    ("phpinfo.php", "debug", Severity.MEDIUM),
    ("info.php", "debug", Severity.MEDIUM),
    ("test.php", "debug", Severity.LOW),
    # --- informational files ---
    ("robots.txt", "info", Severity.INFO),
    ("sitemap.xml", "info", Severity.INFO),
    (".well-known/security.txt", "info", Severity.INFO),
    ("crossdomain.xml", "info", Severity.INFO),
    # --- common directories ---
    ("backup/", "dir", Severity.MEDIUM),
    ("uploads/", "dir", Severity.LOW),
    ("files/", "dir", Severity.LOW),
    ("tmp/", "dir", Severity.LOW),
    ("old/", "dir", Severity.LOW),
    ("test/", "dir", Severity.LOW),
    ("dev/", "dir", Severity.LOW),
]


# Bundled default corpus: SecLists Discovery/Web-Content/common.txt (~4700 paths).
_BUNDLED_WORDLIST = os.path.join(os.path.dirname(__file__), "data", "common.txt")


def _categorize(path: str) -> tuple[str, Severity]:
    """Assign a category + severity to a bare path by pattern.

    Used for wordlist entries that carry no metadata (e.g. SecLists common.txt),
    so the big list still produces severity-graded findings. Ordered most- to
    least-sensitive.
    """
    p = path.lower().lstrip("/")
    base = p.rstrip("/")

    # version control / secrets
    if any(base.startswith(v) or f"/{v}" in base for v in
           (".git", ".svn", ".hg", ".bzr")):
        return "secrets", Severity.HIGH
    if any(t in base for t in (".env", "id_rsa", "id_dsa", ".ssh", ".pem",
                               ".npmrc", ".pgpass", ".aws", "secret", "credential",
                               "private_key", "privatekey")):
        return "secrets", Severity.HIGH
    # backups / dumps
    if base.endswith((".bak", ".old", ".zip", ".tar", ".tar.gz", ".tgz", ".gz",
                      ".sql", ".dump", ".backup", ".swp", ".save", ".orig", "~")) \
            or "backup" in base or "dump" in base:
        return "backup", Severity.HIGH
    # config
    if any(t in base for t in ("wp-config", "web.config", ".htpasswd",
                               "settings.py", "application.yml", "appsettings")):
        return "config", Severity.HIGH
    if any(t in base for t in ("config", ".htaccess", ".ini", ".conf")):
        return "config", Severity.MEDIUM
    # high-value admin tooling
    if any(t in base for t in ("phpmyadmin", "adminer")):
        return "admin", Severity.HIGH
    # debug / actuator
    if "actuator/env" in base or "actuator/heapdump" in base:
        return "debug", Severity.HIGH
    if any(t in base for t in ("phpinfo", "info.php", "server-status",
                               "server-info", "actuator", "metrics", "debug",
                               "trace.axd", "elmah")):
        return "debug", Severity.MEDIUM
    # admin surfaces
    if any(t in base for t in ("admin", "manage", "cpanel", "dashboard",
                               "console", "webadmin", "backend")):
        return "admin", Severity.MEDIUM
    # auth
    if any(t in base for t in ("login", "signin", "sign-in", "signup",
                               "register", "logout", "auth", "oauth", "sso",
                               "password", "passwd")):
        return "auth", Severity.MEDIUM
    # api
    if any(t in base for t in ("api", "graphql", "swagger", "openapi", "wsdl",
                               "soap", "rest")):
        return "api", Severity.MEDIUM
    # informational
    if base in ("robots.txt", "sitemap.xml", "humans.txt", "crossdomain.xml") \
            or "security.txt" in base:
        return "info", Severity.INFO
    return "common", Severity.LOW


def _load_wordlist(extra_path: str | None, quick: bool) -> list[tuple[str, str, Severity]]:
    entries: dict[str, tuple[str, str, Severity]] = {}

    # 1) bundled SecLists common.txt (default corpus), unless --content-quick
    if not quick and os.path.isfile(_BUNDLED_WORDLIST):
        try:
            with open(_BUNDLED_WORDLIST, "r", encoding="utf-8", errors="replace") as fh:
                for line in fh:
                    p = line.strip()
                    if p and not p.startswith("#"):
                        p = p.lstrip("/")
                        cat, sev = _categorize(p)
                        entries[p] = (p, cat, sev)
        except OSError:
            pass

    # 2) curated list — overrides bundled entries with hand-tuned metadata
    for p, cat, sev in _PATHS:
        entries[p] = (p, cat, sev)

    # 3) user-supplied extra paths (appended)
    if extra_path:
        try:
            with open(extra_path, "r", encoding="utf-8") as fh:
                for line in fh:
                    p = line.strip()
                    if p and not p.startswith("#"):
                        p = p.lstrip("/")
                        entries.setdefault(p, (p, *_categorize(p)))
        except OSError:
            pass

    return list(entries.values())


class ContentDiscovery:
    def __init__(self, config: Config, scope: ScopeEngine):
        self.config = config
        self.scope = scope
        self.paths = _load_wordlist(getattr(config, "content_wordlist", None),
                                    quick=getattr(config, "content_quick", False))

    # -- persistent (keep-alive) connection I/O -------------------------- #
    def _open(self, ip: str, port: int, scheme: str):
        if scheme == "https":
            ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
            ctx.check_hostname = False
            ctx.verify_mode = ssl.CERT_NONE
            return http.client.HTTPSConnection(
                ip, port, timeout=self.config.timeout, context=ctx)
        return http.client.HTTPConnection(ip, port, timeout=self.config.timeout)

    def _read_bounded(self, resp, keep: int = _MAX_BODY,
                      max_drain: int = 2 * 1024 * 1024):
        """Read the body: keep the first `keep` bytes, fully drain the rest so
        the connection can be reused. Returns (head, total_len, fully_drained)."""
        head = b""
        total = 0
        fully = True
        while True:
            chunk = resp.read(65536)
            if not chunk:
                break
            total += len(chunk)
            if len(head) < keep:
                head += chunk[: keep - len(head)]
            if total > max_drain:
                fully = False          # too big to safely drain -> don't reuse
                break
        return head, total, fully

    def _request_on(self, conn, ip, port, scheme, host_header, path):
        """One keep-alive GET on a (possibly reused) connection. Returns
        (conn, result|None); reopens the connection on error and retries once."""
        headers = {
            "Host": host_header,
            "User-Agent": "netassess/1.0 (authorized security assessment)",
            "Accept": "*/*",
            "Connection": "keep-alive",
        }
        for _attempt in range(2):
            if not self.scope.authorize(ip, port).allowed:
                return conn, None
            with self.scope.slot(ip, port) as s:
                if not s.allowed:
                    return conn, None
                try:
                    if conn is None:
                        conn = self._open(ip, port, scheme)
                    conn.request("GET", "/" + path.lstrip("/"), headers=headers)
                    resp = conn.getresponse()
                    head, total, fully = self._read_bounded(resp)
                    status = resp.status
                    loc = resp.getheader("Location", "")
                    reuse = fully and resp.getheader("Connection", "").lower() != "close"
                    if not reuse:
                        try:
                            conn.close()
                        except OSError:
                            pass
                        conn = None
                    return conn, (status, total, head, loc)
                except (http.client.HTTPException, ssl.SSLError, socket.timeout,
                        OSError):
                    try:
                        if conn:
                            conn.close()
                    except OSError:
                        pass
                    conn = None          # retry once with a fresh connection
        return conn, None

    def _baseline(self, ip, port, scheme, host_header):
        """Detect soft-404: does the server answer 200 to nonsense paths?"""
        lengths = []
        status_200 = False
        conn = None
        for _ in range(2):
            rnd = "".join(random.choices(string.ascii_lowercase, k=16))
            conn, r = self._request_on(conn, ip, port, scheme, host_header, rnd)
            if r and r[0] == 200:
                status_200 = True
                lengths.append(r[1])
        if conn:
            try:
                conn.close()
            except OSError:
                pass
        base_len = sum(lengths) / len(lengths) if lengths else 0
        return status_200, base_len

    # -- per-service scan (pool of reused connections) ------------------- #
    def scan_service(self, host: Host, svc: HTTPService) -> list[Finding]:
        ip, port, scheme = svc.ip, svc.port, svc.scheme
        host_header = host.hostnames[0] if host.hostnames else ip
        soft404, base_len = self._baseline(ip, port, scheme, host_header)

        q: "Queue" = Queue()
        for entry in self.paths:
            q.put(entry)
        findings: list[Finding] = []
        discovered: list[dict] = []
        lock = threading.Lock()

        hits: list[dict] = []

        def worker():
            conn = None               # this worker's own reused connection
            while True:
                try:
                    path, category, sev = q.get_nowait()
                except Empty:
                    break
                conn, r = self._request_on(conn, ip, port, scheme, host_header, path)
                if r is None:
                    continue
                status, length, body, _loc = r
                if status not in _PRESENT:
                    continue
                if soft404 and status == 200 and abs(length - base_len) < 64:
                    continue
                title = ""
                m = _TITLE_RE.search(body.decode("utf-8", "replace"))
                if m:
                    title = re.sub(r"\s+", " ", m.group(1)).strip()[:120]
                url = f"{scheme}://{ip}:{port}/{path}"
                with lock:
                    hits.append({"path": path, "url": url, "status": status,
                                 "length": length, "category": category,
                                 "sev": sev, "title": title})
            if conn:
                try:
                    conn.close()
                except OSError:
                    pass

        n_workers = max(2, min(self.config.concurrency, 64))
        threads = [threading.Thread(target=worker, daemon=True)
                   for _ in range(n_workers)]
        for t in threads:
            t.start()
        for t in threads:
            t.join()

        hits.sort(key=lambda h: h["path"])
        svc.discovered_paths = [
            {"path": "/" + h["path"], "status": h["status"], "length": h["length"],
             "category": h["category"], "title": h["title"]} for h in hits]
        return make_findings(f"{ip}:{port}", hits, source="content-discovery")



# Public helpers reused by external adapters (e.g. feroxbuster) so all content
# findings share one categorizer, severity model, and schema.
categorize = _categorize

_CAT_TITLES = {
    "secrets": "Exposed sensitive file",
    "config": "Exposed configuration file",
    "backup": "Exposed backup/database file",
    "admin": "Administrative interface reachable",
    "auth": "Authentication endpoint reachable",
    "api": "API endpoint reachable",
    "api-docs": "API documentation exposed",
    "debug": "Debug/status endpoint reachable",
    "info-leak": "Information-leak artifact exposed",
    "info": "Informational file present",
    "dir": "Common directory reachable",
    "common": "Path reachable",
    "custom": "Path reachable",
}


def make_path_finding(asset: str, path: str, url: str, status: int,
                      category: str, sev: Severity, title: str = "",
                      source: str = "content-discovery") -> Finding:
    # protected (401/403) is lower risk than openly accessible (200)
    if status in (401, 403):
        note = f"present but access-controlled (HTTP {status})"
        eff_sev = _downgrade(sev)
        conf = Confidence.HIGH
    else:
        note = f"accessible (HTTP {status})"
        eff_sev = sev
        conf = Confidence.HIGH if status == 200 else Confidence.MEDIUM
    base_title = _CAT_TITLES.get(category, "Path reachable")
    return Finding(
        title=f"{base_title}: /{path.lstrip('/')}",
        asset=asset,
        evidence=f"{url} -> {note}" + (f"; title={title!r}" if title else ""),
        description=f"Content discovery found `/{path.lstrip('/')}` on this "
                    f"web service ({note}).",
        why_it_matters=_why(category),
        severity=eff_sev, confidence=conf,
        impact=_impact(category),
        remediation=_remediation(category),
        validation=(ValidationState.CONFIRMED if status == 200
                    else ValidationState.OBSERVED),
        source=source, category=f"content-{category}",
    )


# low-signal categories: collapse into ONE "Reachable paths" finding per host,
# instead of a separate finding per path. High-value categories stay individual.
GROUPED_CATEGORIES = {"common", "dir", "info", "info-leak", "custom"}


def make_findings(asset: str, hits: list[dict], source: str = "content-discovery"
                  ) -> list[Finding]:
    """Turn per-path hits into findings: high-value paths get their own finding;
    generic/low-signal paths are grouped into a single 'Reachable paths' entry
    per host listing all the endpoints."""
    findings: list[Finding] = []
    grouped: list[dict] = []
    for h in hits:
        if h["category"] in GROUPED_CATEGORIES:
            grouped.append(h)
        else:
            findings.append(make_path_finding(
                asset, h["path"], h["url"], h["status"], h["category"],
                h.get("sev", Severity.LOW), h.get("title", ""), source))
    if grouped:
        grouped.sort(key=lambda x: x["path"])
        listing = ", ".join(f"/{g['path'].lstrip('/')} ({g['status']})"
                            for g in grouped)
        findings.append(Finding(
            title="Reachable paths (content discovery)",
            asset=asset,
            evidence=f"{len(grouped)} path(s): {listing}"[:1500],
            description="Content discovery found additional reachable paths on this "
                        "web service (generic/low-signal). Each is listed in the "
                        "evidence with its HTTP status.",
            why_it_matters="Reachable paths expand the attack surface; review for "
                           "anything sensitive or unintended.",
            severity=Severity.LOW, confidence=Confidence.MEDIUM,
            impact="Additional reachable endpoints to review for authn/authz.",
            remediation="Review the listed paths; restrict or remove any that "
                        "should not be publicly reachable.",
            validation=ValidationState.OBSERVED, source=source,
            category="content-paths",
        ))
    return findings


def _downgrade(sev: Severity) -> Severity:
    order = [Severity.INFO, Severity.LOW, Severity.MEDIUM, Severity.HIGH,
             Severity.CRITICAL]
    i = order.index(sev)
    return order[max(0, i - 1)]


def _why(category: str) -> str:
    return {
        "secrets": "Exposed secrets/keys can lead directly to full compromise.",
        "config": "Configuration files often leak credentials and internal detail.",
        "backup": "Backups/DB dumps may expose the entire application's data.",
        "admin": "Admin panels are prime targets for credential and auth attacks.",
        "auth": "Authentication endpoints expand the login attack surface.",
        "api": "APIs may expose data or actions with weaker controls than the UI.",
        "api-docs": "API docs reveal endpoints, parameters and internal structure.",
        "debug": "Debug/status endpoints can leak environment and internal data.",
        "info-leak": "Editor/OS artifacts can disclose paths and structure.",
        "info": "Standard metadata file; low sensitivity.",
        "dir": "Reachable directories may permit listing or host stale content.",
        "custom": "Reachable path from the supplied wordlist.",
    }.get(category, "Reachable path — review for exposure.")


def _impact(category: str) -> str:
    high = {"secrets", "config", "backup"}
    if category in high:
        return "Potential direct disclosure of credentials/data if contents are sensitive."
    return "Expands the reachable attack surface; verify authentication/authorization."


def _remediation(category: str) -> str:
    return {
        "secrets": "Remove the file from the web root; rotate any leaked secrets.",
        "config": "Block access to config files; move secrets to env/secret stores.",
        "backup": "Remove backups from web-accessible paths; store them offline.",
        "admin": "Restrict admin panels to trusted networks/VPN; enforce MFA.",
        "auth": "Ensure rate limiting, MFA and monitoring on auth endpoints.",
        "api": "Require authentication/authorization and rate limiting on the API.",
        "api-docs": "Do not expose API docs publicly in production.",
        "debug": "Disable debug/status endpoints in production or restrict access.",
        "info-leak": "Remove editor/VCS/OS artifacts from deployed content.",
        "info": "No action required unless it leaks sensitive detail.",
        "dir": "Disable directory listing; remove stale content.",
        "custom": "Review whether this path should be publicly reachable.",
    }.get(category, "Review exposure and restrict if unnecessary.")

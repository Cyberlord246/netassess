"""Curated, offline CVE knowledge base.

This is an ILLUSTRATIVE, extensible starter set of well-known CVEs for common
network services — NOT a comprehensive vulnerability database. It exists so the
platform can produce version-based CVE *leads* with zero network access. Every
match is emitted as NEEDS_VALIDATION: a banner version is not proof a host is
vulnerable (back-ported patches, distro versioning, and disabled features are
common), so results must be confirmed.

Extend it by editing this list, or supply your own via ``--cve-db file.json``
(same schema) and/or enable ``--cve-online`` for live NVD enrichment.

Schema per entry:
    id            : CVE identifier
    product       : canonical product name
    keywords      : substrings matched (case-insensitive) against the observed
                    product/banner/technology string
    ranges        : list of {introduced?, fixed?, last_affected?} (see version.in_range)
    cvss          : CVSS base score (float)
    severity      : info|low|medium|high|critical
    summary       : one-line description
    references    : list of URLs
"""
from __future__ import annotations

import json

# fmt: off
CVE_DB: list[dict] = [
    {
        "id": "CVE-2021-41773", "product": "apache httpd",
        "keywords": ["apache", "httpd"],
        "ranges": [{"introduced": "2.4.49", "fixed": "2.4.50"}],
        "cvss": 7.5, "severity": "high",
        "summary": "Apache HTTP Server 2.4.49 path traversal; can lead to RCE if "
                   "mod_cgi is enabled and 'require all denied' is not set.",
        "references": ["https://nvd.nist.gov/vuln/detail/CVE-2021-41773"],
    },
    {
        "id": "CVE-2021-42013", "product": "apache httpd",
        "keywords": ["apache", "httpd"],
        "ranges": [{"introduced": "2.4.49", "fixed": "2.4.51"}],
        "cvss": 9.8, "severity": "critical",
        "summary": "Apache HTTP Server 2.4.49/2.4.50 path traversal and RCE "
                   "(incomplete fix for CVE-2021-41773).",
        "references": ["https://nvd.nist.gov/vuln/detail/CVE-2021-42013"],
    },
    {
        "id": "CVE-2018-15473", "product": "openssh",
        "keywords": ["openssh"],
        "ranges": [{"fixed": "7.7"}],
        "cvss": 5.3, "severity": "medium",
        "summary": "OpenSSH < 7.7 username enumeration via crafted authentication "
                   "requests (timing/behaviour difference).",
        "references": ["https://nvd.nist.gov/vuln/detail/CVE-2018-15473"],
    },
    {
        "id": "CVE-2023-38408", "product": "openssh",
        "keywords": ["openssh"],
        "ranges": [{"fixed": "9.3.2"}],  # 9.3p2
        "cvss": 9.8, "severity": "critical",
        "summary": "OpenSSH ssh-agent PKCS#11 remote code execution when an agent "
                   "with forwarding is exposed (fixed in 9.3p2).",
        "references": ["https://nvd.nist.gov/vuln/detail/CVE-2023-38408"],
    },
    {
        "id": "CVE-2024-6387", "product": "openssh",
        "keywords": ["openssh"],
        "ranges": [{"introduced": "8.5.1", "fixed": "9.8.1"}],  # 8.5p1 .. <9.8p1
        "cvss": 8.1, "severity": "high",
        "summary": "OpenSSH 'regreSSHion' unauthenticated RCE via signal handler "
                   "race on glibc Linux (8.5p1 up to but not including 9.8p1).",
        "references": ["https://nvd.nist.gov/vuln/detail/CVE-2024-6387"],
    },
    {
        "id": "CVE-2019-20372", "product": "nginx",
        "keywords": ["nginx"],
        "ranges": [{"fixed": "1.17.7"}],
        "cvss": 5.3, "severity": "medium",
        "summary": "nginx < 1.17.7 HTTP request smuggling via error_page handling.",
        "references": ["https://nvd.nist.gov/vuln/detail/CVE-2019-20372"],
    },
    {
        "id": "CVE-2021-23017", "product": "nginx",
        "keywords": ["nginx"],
        "ranges": [{"introduced": "0.6.18", "fixed": "1.21.0"}],
        "cvss": 7.7, "severity": "high",
        "summary": "nginx resolver off-by-one heap write; potential worker crash "
                   "or code execution (fixed in 1.21.0 / 1.20.1).",
        "references": ["https://nvd.nist.gov/vuln/detail/CVE-2021-23017"],
    },
    {
        "id": "CVE-2014-0160", "product": "openssl",
        "keywords": ["openssl"],
        "ranges": [{"introduced": "1.0.1", "fixed": "1.0.1.7"}],  # 1.0.1 .. <1.0.1g
        "cvss": 7.5, "severity": "high",
        "summary": "OpenSSL 'Heartbleed' TLS heartbeat information disclosure "
                   "(1.0.1 through 1.0.1f).",
        "references": ["https://nvd.nist.gov/vuln/detail/CVE-2014-0160"],
    },
    {
        "id": "CVE-2011-2523", "product": "vsftpd",
        "keywords": ["vsftpd"],
        "ranges": [{"introduced": "2.3.4", "last_affected": "2.3.4"}],
        "cvss": 10.0, "severity": "critical",
        "summary": "vsftpd 2.3.4 backdoor command execution (malicious upstream "
                   "tarball) — smiley-face trigger opens a root shell on 6200/tcp.",
        "references": ["https://nvd.nist.gov/vuln/detail/CVE-2011-2523"],
    },
    {
        "id": "CVE-2019-10149", "product": "exim",
        "keywords": ["exim"],
        "ranges": [{"introduced": "4.87", "last_affected": "4.91"}],
        "cvss": 9.8, "severity": "critical",
        "summary": "Exim 4.87–4.91 remote command execution via crafted recipient "
                   "address ('Return of the WIZard').",
        "references": ["https://nvd.nist.gov/vuln/detail/CVE-2019-10149"],
    },
    {
        "id": "CVE-2020-11651", "product": "saltstack",
        "keywords": ["salt", "saltstack"],
        "ranges": [{"fixed": "2019.2.4"}, {"introduced": "3000", "fixed": "3000.2"}],
        "cvss": 9.8, "severity": "critical",
        "summary": "SaltStack Salt master authentication bypass leading to RCE.",
        "references": ["https://nvd.nist.gov/vuln/detail/CVE-2020-11651"],
    },
]
# fmt: on


def load_db(path: str | None = None) -> list[dict]:
    """Return the built-in DB, optionally extended/overridden by a JSON file."""
    db = list(CVE_DB)
    if path:
        db.extend(load_cache_file(path))
    return db


def load_cache_file(path: str) -> list[dict]:
    """Load a CVE JSON file (a bare list, or an object with a "cves" list)."""
    try:
        with open(path, "r", encoding="utf-8") as fh:
            data = json.load(fh)
    except (OSError, json.JSONDecodeError):
        return []
    if isinstance(data, dict) and "cves" in data:
        data = data["cves"]
    return data if isinstance(data, list) else []

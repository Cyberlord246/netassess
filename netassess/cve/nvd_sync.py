"""Offline NVD feed sync.

Downloads CVE data from the NVD 2.0 API *once* (talking to NVD, never to your
targets) and writes it to a local cache in the same schema the CVEEngine uses.
After syncing, CVE correlation runs fully offline against thousands of CVEs with
no extra traffic to assessed hosts.

Sync is scoped to the products netassess actually fingerprints (web servers,
SSH, TLS libs, databases, mail, etc.), which keeps it fast and relevant; extend
``PRODUCTS`` or pass your own list. Version ranges are extracted from each CVE's
CPE applicability data (``versionStartIncluding`` / ``versionEndExcluding`` …)
and mapped to the engine's introduced/fixed/last_affected model.

Rate limits: NVD allows ~5 requests / 30s without a key, ~50 / 30s with one.
Set ``NVD_API_KEY`` in the environment for the faster tier. Network/parse errors
are non-fatal — whatever was fetched is still saved.
"""
from __future__ import annotations

import json
import os
import time
import urllib.parse
import urllib.request

_NVD_URL = "https://services.nvd.nist.gov/rest/json/cves/2.0"

# Products netassess can fingerprint -> how to query NVD + how to match locally.
#   cpe      : CPE 2.3 product prefix used as NVD `virtualMatchString`
#   keywords : substrings matched against observed product/banner/tech text
PRODUCTS: list[dict] = [
    {"name": "nginx", "cpe": "cpe:2.3:a:f5:nginx", "keywords": ["nginx"]},
    {"name": "apache httpd", "cpe": "cpe:2.3:a:apache:http_server",
     "keywords": ["apache", "httpd"]},
    {"name": "openssh", "cpe": "cpe:2.3:a:openbsd:openssh", "keywords": ["openssh"]},
    {"name": "openssl", "cpe": "cpe:2.3:a:openssl:openssl", "keywords": ["openssl"]},
    {"name": "mysql", "cpe": "cpe:2.3:a:oracle:mysql", "keywords": ["mysql"]},
    {"name": "mariadb", "cpe": "cpe:2.3:a:mariadb:mariadb", "keywords": ["mariadb"]},
    {"name": "postgresql", "cpe": "cpe:2.3:a:postgresql:postgresql",
     "keywords": ["postgresql", "postgres"]},
    {"name": "redis", "cpe": "cpe:2.3:a:redis:redis", "keywords": ["redis"]},
    {"name": "mongodb", "cpe": "cpe:2.3:a:mongodb:mongodb", "keywords": ["mongodb"]},
    {"name": "exim", "cpe": "cpe:2.3:a:exim:exim", "keywords": ["exim"]},
    {"name": "postfix", "cpe": "cpe:2.3:a:postfix:postfix", "keywords": ["postfix"]},
    {"name": "dovecot", "cpe": "cpe:2.3:a:dovecot:dovecot", "keywords": ["dovecot"]},
    {"name": "vsftpd", "cpe": "cpe:2.3:a:vsftpd_project:vsftpd", "keywords": ["vsftpd"]},
    {"name": "proftpd", "cpe": "cpe:2.3:a:proftpd:proftpd", "keywords": ["proftpd"]},
    {"name": "tomcat", "cpe": "cpe:2.3:a:apache:tomcat", "keywords": ["tomcat", "coyote"]},
    {"name": "jetty", "cpe": "cpe:2.3:a:eclipse:jetty", "keywords": ["jetty"]},
    {"name": "samba", "cpe": "cpe:2.3:a:samba:samba", "keywords": ["samba"]},
    {"name": "php", "cpe": "cpe:2.3:a:php:php", "keywords": ["php"]},
    {"name": "lighttpd", "cpe": "cpe:2.3:a:lighttpd:lighttpd", "keywords": ["lighttpd"]},
    {"name": "haproxy", "cpe": "cpe:2.3:a:haproxy:haproxy", "keywords": ["haproxy"]},
    {"name": "squid", "cpe": "cpe:2.3:a:squid-cache:squid", "keywords": ["squid"]},
    {"name": "openresty", "cpe": "cpe:2.3:a:openresty:openresty", "keywords": ["openresty"]},
]

_SEV_ORDER = {"CRITICAL": 4, "HIGH": 3, "MEDIUM": 2, "LOW": 1, "NONE": 0}


def default_cache_path() -> str:
    return os.path.join(os.path.expanduser("~"), ".netassess", "nvd.json")


# --------------------------------------------------------------------------- #
# parsing (pure, unit-testable — no network)
# --------------------------------------------------------------------------- #
def _cpe_version(criteria: str) -> str:
    parts = criteria.split(":")
    # cpe:2.3:a:vendor:product:version:... -> version at index 5
    return parts[5] if len(parts) > 5 else "*"


def _ranges_from_cpematch(node_matches: list[dict], cpe_prefix: str) -> list[dict]:
    ranges: list[dict] = []
    for m in node_matches:
        if not m.get("vulnerable"):
            continue
        criteria = m.get("criteria", "")
        if not criteria.startswith(cpe_prefix):
            continue
        introduced = m.get("versionStartIncluding") or m.get("versionStartExcluding")
        fixed = m.get("versionEndExcluding")
        last_affected = m.get("versionEndIncluding")
        if introduced or fixed or last_affected:
            r = {}
            if introduced:
                r["introduced"] = introduced
            if fixed:
                r["fixed"] = fixed
            if last_affected:
                r["last_affected"] = last_affected
            ranges.append(r)
        else:
            ver = _cpe_version(criteria)
            if ver not in ("*", "-", ""):
                ranges.append({"introduced": ver, "last_affected": ver})
    return ranges


def _iter_cpematches(configurations) -> list[dict]:
    out = []
    for cfg in configurations or []:
        for node in cfg.get("nodes", []):
            out.extend(node.get("cpeMatch", []))
    return out


def _severity_and_score(cve: dict) -> tuple[str, float | None]:
    metrics = cve.get("metrics", {})
    for key in ("cvssMetricV31", "cvssMetricV30", "cvssMetricV2"):
        arr = metrics.get(key)
        if arr:
            m = arr[0]
            data = m.get("cvssData", {})
            score = data.get("baseScore")
            sev = (m.get("baseSeverity") or data.get("baseSeverity") or "").upper()
            if not sev and score is not None:  # CVSS v2 has no baseSeverity
                sev = ("CRITICAL" if score >= 9 else "HIGH" if score >= 7
                       else "MEDIUM" if score >= 4 else "LOW")
            return (sev or "MEDIUM"), score
    return "MEDIUM", None


def parse_response(data: dict, cpe_prefix: str, keywords: list[str]) -> list[dict]:
    """Turn one NVD 2.0 API page into CVEEngine schema entries."""
    entries: list[dict] = []
    for item in data.get("vulnerabilities", []):
        cve = item.get("cve", {})
        cid = cve.get("id")
        if not cid:
            continue
        ranges = _ranges_from_cpematch(
            _iter_cpematches(cve.get("configurations")), cpe_prefix)
        if not ranges:
            continue  # no usable version applicability for this product
        descs = cve.get("descriptions", [])
        summary = next((d.get("value", "") for d in descs
                        if d.get("lang") == "en"), "")
        sev, score = _severity_and_score(cve)
        refs = [r.get("url", "") for r in cve.get("references", [])][:4]
        entries.append({
            "id": cid,
            "product": keywords[0],
            "keywords": list(keywords),
            "ranges": ranges,
            "cvss": score,
            "severity": sev.lower(),
            "summary": summary[:400],
            "references": refs,
        })
    return entries


def merge_entries(existing: list[dict], new: list[dict]) -> list[dict]:
    """Merge by CVE id, unioning keywords and version ranges."""
    by_id: dict[str, dict] = {e["id"]: e for e in existing}
    for e in new:
        cur = by_id.get(e["id"])
        if cur is None:
            by_id[e["id"]] = e
            continue
        cur["keywords"] = sorted(set(cur["keywords"]) | set(e["keywords"]))
        seen = {json.dumps(r, sort_keys=True) for r in cur["ranges"]}
        for r in e["ranges"]:
            if json.dumps(r, sort_keys=True) not in seen:
                cur["ranges"].append(r)
    return list(by_id.values())


# --------------------------------------------------------------------------- #
# network sync
# --------------------------------------------------------------------------- #
class NVDSync:
    def __init__(self, timeout: float = 30.0, page_size: int = 2000):
        self.timeout = timeout
        self.page_size = page_size
        self.api_key = os.environ.get("NVD_API_KEY")
        self.min_interval = 0.7 if self.api_key else 6.5
        self._last = 0.0

    def _throttle(self):
        wait = self.min_interval - (time.monotonic() - self._last)
        if wait > 0:
            time.sleep(wait)
        self._last = time.monotonic()

    def _get(self, params: dict, retries: int = 3) -> dict | None:
        """GET one page, retrying on the transient failures the keyless NVD API
        is prone to (403/429/5xx/timeouts) with backoff."""
        url = f"{_NVD_URL}?{urllib.parse.urlencode(params)}"
        for attempt in range(retries):
            self._throttle()
            req = urllib.request.Request(url, headers={"User-Agent": "netassess/1.0"})
            if self.api_key:
                req.add_header("apiKey", self.api_key)
            try:
                with urllib.request.urlopen(req, timeout=self.timeout) as resp:
                    return json.loads(resp.read().decode("utf-8", "replace"))
            except Exception:
                # backoff grows; NVD throttles keyless clients aggressively
                time.sleep(min(2 ** attempt * self.min_interval, 30))
        return None

    def fetch_product(self, product: dict, log=lambda *a: None) -> list[dict]:
        cpe = product["cpe"]
        collected: list[dict] = []
        start = 0
        total = None
        while True:
            data = self._get({
                "virtualMatchString": cpe,
                "resultsPerPage": self.page_size,
                "startIndex": start,
            })
            if data is None:
                log(f"    ! fetch failed for {product['name']} at index {start}")
                break
            page = parse_response(data, cpe, product["keywords"])
            collected = merge_entries(collected, page)
            total = data.get("totalResults", 0)
            got = data.get("resultsPerPage", 0) or len(data.get("vulnerabilities", []))
            start += got if got else self.page_size
            if start >= (total or 0) or got == 0:
                break
        return collected

    def sync(self, products: list[dict] | None = None,
             out_path: str | None = None, log=print) -> dict:
        products = products or PRODUCTS
        out_path = out_path or default_cache_path()
        all_entries: list[dict] = []
        log(f"[nvd-sync] syncing {len(products)} product(s) from NVD "
            f"({'with' if self.api_key else 'no'} API key)…")
        for i, product in enumerate(products, 1):
            log(f"  [{i}/{len(products)}] {product['name']}…")
            entries = self.fetch_product(product, log=log)
            all_entries = merge_entries(all_entries, entries)
            log(f"      {len(entries)} CVE(s); total so far {len(all_entries)}")

        os.makedirs(os.path.dirname(os.path.abspath(out_path)), exist_ok=True)
        payload = {
            "source": "nvd-2.0",
            "synced": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
            "count": len(all_entries),
            "cves": all_entries,
        }
        tmp = out_path + ".tmp"
        with open(tmp, "w", encoding="utf-8") as fh:
            json.dump(payload, fh, indent=2)
        os.replace(tmp, out_path)
        log(f"[nvd-sync] wrote {len(all_entries)} CVE(s) -> {out_path}")
        return {"count": len(all_entries), "path": out_path}

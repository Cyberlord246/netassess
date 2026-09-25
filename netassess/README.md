# netassess — Authorized Network Attack-Surface Assessment Platform

A modular, explainable, **safe-by-default** network assessment agent. Given a
list of IPs/CIDRs you are **explicitly authorized** to test, it builds a
structured attack-surface inventory: live hosts → reverse DNS → open ports →
services/versions → protocol probes → HTTP/TLS analysis → technology
identification → safe vulnerability heuristics → CVE correlation → correlation →
prioritization → a comprehensive report (Markdown + JSON + HTML).

It runs with **zero external dependencies** (Python 3.10+ stdlib only). If
`nmap` is on the PATH it is used automatically for richer service/version
detection; otherwise a pure-Python TCP connect scanner is used.

> ⚠️ **Authorization is mandatory.** Only assess systems you own or have written
> permission to test. The Scope Engine is a hard gate on every network
> operation, but it cannot grant you authorization you do not have.

## Safety model

* **Scope Engine (mandatory gate).** Every network-active operation is checked
  against the authorized include-list, the exclude-list, and port policy
  *before* it runs, and each decision is logged. Hosts discovered during the
  assessment (in redirects, DNS, etc.) are **never** auto-added to scope.
* **Non-destructive only.** Banner/metadata reads, standard TLS handshakes,
  single GET requests, read-only protocol identification. No exploitation, no
  fuzzing, no credential attacks, no writes to remote state.
* **Rate & concurrency limits.** A token-bucket rate limiter and a bounded
  concurrency semaphore are enforced inside the gate.
* **Honest confidence.** Version-derived issues are marked `NEEDS_VALIDATION`;
  nothing is asserted `CONFIRMED` without direct evidence.

## Install / run

No install needed. From the directory containing the `netassess/` package:

```bash
python -m netassess network scan --targets targets.txt --mode auto
```

## Usage

```bash
# Full assessment from a file of IPs/CIDRs
python -m netassess network scan --targets targets.txt

# Inline targets, deeper (still safe) probing, custom ports
python -m netassess network scan --targets 192.0.2.10,192.0.2.20 \
    --ports 1-1024 --deep --output ./out

# Full TCP range, tuned performance
python -m netassess network scan --targets targets.txt \
    --full-port-scan --concurrency 100 --rate 300 --timeout 2

# AI-assisted task ordering (needs ANTHROPIC_API_KEY; falls back safely)
python -m netassess network scan --targets targets.txt \
    --mode ai --ai-provider anthropic

# CVE correlation: offline by default; add live NVD enrichment or a custom DB
python -m netassess network scan --targets targets.txt --cve-online
python -m netassess network scan --targets targets.txt --cve-db my-cves.json
python -m netassess network scan --targets targets.txt --no-cve --no-html

# Validate scope + test the authorization gate without touching the network
python -m netassess scope check --targets 10.0.0.0/24 \
    --exclude 10.0.0.1 --test 10.0.0.5,8.8.8.8

# Regenerate a report from saved state
python -m netassess report --state out/state.json

# Diff two runs — what changed since last time? (great for re-tests / monitoring)
python -m netassess diff --old baseline/state.json --new latest/state.json \
    --output diff-out --fail-on worse
```

### Key options

| Flag | Meaning |
|---|---|
| `--targets` | file path, or comma list of IPs/CIDRs (required) |
| `--exclude` | file/comma IPs/CIDRs to exclude (always wins) |
| `--mode` | `deterministic` (default) · `ai` · `auto` |
| `--ports` | explicit set, e.g. `22,80,443` or `1-1024` (overrides the default) |
| `--common-ports` | fast preset: 40 high-signal ports instead of top-1000 |
| `--full-port-scan` | scan all 65,535 TCP ports |
| `--deep` | deeper service detection (still non-destructive) |
| `--concurrency` / `--rate` / `--timeout` / `--retries` | performance & safety limits |
| `--content-discovery` | enumerate common web paths (admin/login/api/.env…) on HTTP services |
| `--content-tool` | `auto` (feroxbuster if installed, else built-in), `feroxbuster`, or `builtin` |
| `--content-quick` | use only the small curated list (~70 paths) instead of full SecLists |
| `--content-depth` / `--content-extensions` / `--content-thorough` | feroxbuster tuning |
| `--wordlist` | file of extra paths to append to the content-discovery list |
| `--min-severity` | lowest severity shown in reports (default `medium`; low/info suppressed) |
| `--all-findings` | include every finding (same as `--min-severity info`) |
| `--no-aggregate` | list findings per host instead of grouping across hosts |
| `--cve-online` | enrich CVE findings via NVD (network, opt-in) |
| `--cve-db` | merge an extra CVE JSON file into the built-in KB |
| `--no-cve` / `--no-html` | disable CVE correlation / HTML report |
| `--output` | output directory (report.md, report.json, report.html, state.json) |

## Port selection

By default netassess scans the **canonical Nmap top-1000 TCP ports** (the 1000
highest-frequency service ports), so you get nmap-like coverage without needing
nmap installed. Override it any time:

| Preset | Flag | Ports scanned |
|---|---|---|
| **Top 1000 (default)** | *(nothing)* | **1000** |
| Fast / high-signal | `--common-ports` | 40 |
| Explicit list | `--ports 22,80,443` | exactly those |
| Explicit range | `--ports 1-1024` | 1024 |
| Everything | `--full-port-scan` | 65,535 |

```bash
# default — top 1000
python -m netassess network scan --targets targets.txt

# quick sweep of the 40 most common ports
python -m netassess network scan --targets targets.txt --common-ports

# only web ports
python -m netassess network scan --targets targets.txt --ports 80,443,8080,8443
```

> Larger port sets take longer, especially across many hosts. Tune
> `--concurrency`, `--rate`, and `--timeout` for `--full-port-scan`.

## Architecture

```
Input → Scope Engine → Discovery → Asset Graph → Port Scanner →
Service ID → Protocol Probers → HTTP/TLS Analysis → Technology Detection →
Vulnerability Assessment → Correlation → Prioritization → Report
```

| Module | Responsibility |
|---|---|
| `scope.py` | Mandatory authorization gate, rate/concurrency policy, decision log |
| `config.py` | All tunables and policy |
| `state.py` | Persistent, queryable asset graph (JSON) |
| `discovery.py` | TCP-based live-host discovery (ICMP-independent) |
| `dns_recon.py` | Reverse DNS (PTR) — evidence only, not proof of ownership |
| `ports.py` | Pure-Python scanner + optional Nmap backend |
| `services.py` | Port+banner service identification |
| `probers/` | `ServiceProbe` interface: HTTP, TLS, SSH, SMTP, DNS, SMB, DB, Generic |
| `techdetect.py` | HTTP technology fingerprinting with evidence/confidence |
| `vuln/` | Safe, evidence-gated vulnerability heuristics + external-scanner hook |
| `cve/` | Offline CVE knowledge base + version-range matching + optional NVD enrichment |
| `report_html.py` | Self-contained HTML report (inline CSS, severity-colored cards) |
| `diff.py` | Compare two `state.json` runs (new/closed ports, version changes, new/resolved findings) |
| `correlation.py` | IP→host→port→service→version→tech→finding chains |
| `prioritize.py` | Explainable, evidence-weighted risk scoring |
| `report.py` | Markdown + JSON report generator |
| `ai/` | Orchestrator: deterministic planner + optional LLM task-ranking |
| `adapters/` | External-tool adapters (Nmap) returning structured data |

### Adding a probe

Implement `ServiceProbe` (`matches()` + `probe()`), return a `ProbeResult` with
structured `data` and `Finding`s, and register the class in
`probers/__init__.py`. Always call `self.in_scope(ip, port)` (or use
`self.scope.slot(...)`) before any connection.

### Integrating an external vulnerability scanner

Implement an adapter with `available()` and `scan(graph) -> list[Finding]`
(mapping results into the common `Finding` schema) and pass it to
`VulnAssessmentEngine(config, scanner_adapters=[...])`. The platform runs fully
without any external scanner installed.

## Outputs

* `report.md` — human-readable report (all required sections).
* `report.html` — self-contained HTML report (inline CSS, dark/light, severity-colored finding cards). No external assets or JS deps.
* `report.json` — machine-readable export (scope, config, full graph, priorities).
* `state.json` — the persistent asset graph (resume / diff / re-report).

## Content discovery (web path enumeration)

With `--content-discovery`, after HTTP services are found the tool requests a
wordlist of common paths on each one and reports which exist, so you can see the
reachable web attack surface.

* **Default wordlist:** the bundled **SecLists `common.txt`** (~4,700 paths) at
  [`data/common.txt`](data/common.txt). Bare paths are auto-graded by pattern
  (e.g. `.env`/`.git`/backups → high, `admin`/`api`/`login` → medium), and a
  curated list layers hand-tuned severities/wording on top.
* **`--content-quick`** uses only the small curated list (~70 high-signal paths)
  — much faster, ideal for a first pass or many hosts.
* **`--wordlist FILE`** appends your own paths.

```bash
# default: full SecLists common.txt (~4,700 paths), parallelized
python -m netassess network scan --targets targets.txt --content-discovery

# fast curated pass (~70 paths)
python -m netassess network scan --targets targets.txt --content-discovery --content-quick

# add custom paths on top of the default corpus
python -m netassess network scan --targets targets.txt --content-discovery --wordlist extra-paths.txt
```

It is **safe and read-only**:

* **GET requests only** — it checks what *exists*; it never submits forms,
  authenticates, or acts on what it finds.
* **Scope-gated + rate-limited** — every request goes through the same mandatory
  scope/rate/concurrency gate as the rest of the tool.
* **Known wordlist** — the standard SecLists `common.txt` (or `--content-quick`
  for the curated subset), parallelized and rate-limited — not blind fuzzing of
  generated strings.
* **Soft-404 calibration** — servers that answer `200` to everything are
  detected, so phantom hits aren't reported.

Findings are severity-graded (e.g. exposed `.env`/backups = high, admin/API =
medium) and access-controlled hits (`401`/`403`) are down-weighted vs. openly
accessible (`200`) ones. All discovered paths are also listed in a **Discovered
Web Content** report section (every severity), while the sensitive ones surface
under Findings.

### Engine: feroxbuster (recommended) or built-in

If **feroxbuster** is installed it is used automatically (fast, recursive, Rust);
otherwise the built-in Python probe runs. Force either with `--content-tool`.

```bash
# auto: feroxbuster if present, else built-in
python -m netassess network scan --targets targets.txt --content-discovery

# force feroxbuster, recurse 2 levels, also check for backups
python -m netassess network scan --targets targets.txt --content-discovery \
    --content-tool feroxbuster --content-depth 2 --content-extensions php,bak,zip,sql \
    --content-thorough
```

The feroxbuster integration is tuned for **signal over noise**:

* `--auto-tune` — feroxbuster detects wildcard/soft-404 pages and dynamically
  adds size/word/line filters, so garbage hits are dropped automatically.
* `--filter-status 404,400,500,501,502,503` — drops not-found and generic error
  noise **while keeping useful non-200 codes** (200/301/302/**401**/**403**/405…),
  which flag protected or existing resources — not just `200`s.
* bounded `--depth` recursion into directories it actually finds.
* `--dont-scan` state-changing paths (logout/delete/…) as a safety guard.
* JSON output normalised into the same severity-graded `Finding` schema as the
  built-in probe (`.env`/`.git`/backups → high, admin/api → medium, `401`/`403`
  down-weighted vs open `200`).

Install feroxbuster: `brew install feroxbuster` /
`apt install feroxbuster` / [releases](https://github.com/epi052/feroxbuster).

> Content discovery is more active than passive probing, so it is **off by
> default**. Only enable it against targets you are authorized to test.

The bundled `data/common.txt` is from [SecLists](https://github.com/danielmiessler/SecLists)
(`Discovery/Web-Content/common.txt`, MIT-licensed). Refresh it by replacing that
file with a newer copy.

## Report signal (severity filter + aggregation)

Reports are kept signal-dense by default:

* **Severity filter** — only findings at **medium and above** are shown. Noise
  like *missing security headers* (low) and *version disclosure* (info) is
  suppressed. Lower it with `--min-severity low|info`, or show everything with
  `--all-findings`.
* **Cross-host aggregation** — the same issue seen on many hosts is collapsed
  into **one entry that lists all affected assets** (e.g. "Deprecated TLS
  versions × 3 hosts"), instead of repeating it per host. Disable with
  `--no-aggregate`.

Both apply only to the human reports (`report.md` / `report.html`). The full,
unfiltered data is always kept in `report.json` and `state.json`, so diffing and
machine processing stay complete.

```bash
# default: medium+, aggregated
python -m netassess network scan --targets targets.txt

# show everything, one row per host
python -m netassess network scan --targets targets.txt --all-findings --no-aggregate

# only high/critical in the report
python -m netassess network scan --targets targets.txt --min-severity high
```

## Diff mode (change monitoring / re-tests)

Every scan writes a `state.json` snapshot. `diff` compares two of them and
surfaces the security-relevant deltas:

```bash
python -m netassess diff --old baseline/state.json --new latest/state.json --output diff-out
```

It reports: **newly opened / closed ports**, new / removed hosts, host status
changes, **service & version changes** (e.g. an SSH downgrade), new HTTP
services, and **new / resolved findings** (including CVE leads, sorted by
severity). Output goes to stdout and, with `--output`, to `diff.md` + `diff.json`.

For pipelines, `--fail-on` sets the exit code:

* `--fail-on any` → exit 1 if *anything* changed.
* `--fail-on worse` → exit 1 only if something got worse (new open ports or new
  findings) — ideal for a scheduled re-test gate.

## CVE correlation

The `cve/` engine extracts `(product, version)` evidence already in the asset
graph (service versions, banners, HTTP `Server` headers, detected technologies)
and matches it against a **curated offline CVE knowledge base** with correct
version-range comparison (handles `2.4.49`, `9.3p2`, `1.0.1f`, etc.).

* **Offline by default** — no network required. A small built-in KB ships in
  [`cve/database.py`](cve/database.py); for real coverage, run the **offline NVD
  sync** once (below). Both are matched fully offline against versions already
  collected — **zero extra traffic to your targets**.
* **`netassess cve sync`** downloads CVE data from the NVD 2.0 API (talking to
  NVD, never your targets) into `~/.netassess/nvd.json`, scoped to the products
  netassess fingerprints. Scans then use it automatically. Example impact:
  OpenSSH 7.4 goes from ~2 built-in matches to ~30+ real, version-matched CVEs.

  ```bash
  # one-time (or periodic) sync — set NVD_API_KEY for a much higher rate limit
  netassess cve sync                       # all fingerprinted products
  netassess cve sync --products nginx,openssh,apache
  ```

  > The keyless NVD API is heavily rate-limited and occasionally flaky (the sync
  > retries with backoff). For a reliable full sync, get a free key at
  > <https://nvd.nist.gov/developers/request-an-api-key> and `export NVD_API_KEY=…`.
* Extend or override with your own file via `--cve-db file.json` (same schema).
* **Opt-in live enrichment** — `--cve-online` queries the NVD 2.0 API (rate-limited,
  cached, best-effort; set `NVD_API_KEY` for a higher limit). This is the only
  component that reaches a third party, and it sends only product/version keywords.
* **Honest by design** — every CVE match is a **lead** (`NEEDS_VALIDATION`), never
  a confirmation: a banner version does not prove exploitability (back-ports,
  distro versioning, disabled features).

## Modes

* **deterministic** — complete baseline assessment with a fixed decision tree;
  no LLM required.
* **ai / auto** — an LLM may *reorder or deprioritise* the deterministic
  candidate task list. It can **never** invent a target, widen scope, or pick a
  forbidden port; all tasks are re-checked by the Scope Engine at execution
  time. Falls back to deterministic planning if no provider is configured.

# netassess — Authorized Network Attack-Surface Assessment Platform

A modular, explainable, **safe-by-default** network assessment agent. Given a
list of IPs/CIDRs you are **explicitly authorized** to test, it builds a
structured attack-surface inventory:

```
scope gate → live hosts + reverse DNS → port scan → service/version ID →
protocol probes (HTTP/HTTPS on any open port, TLS, tech, misconfig) →
virtual-host discovery → default-login exposure → content discovery* →
endpoint/JS analysis → nuclei* / UDP* → vuln heuristics → CVE + KEV/EPSS →
validation → role/anomaly analysis → report (MD / HTML / JSON)
                                        └→ nextphase (phase-2 plan)
```
<sub>* opt-in (`--content-discovery`, `--nuclei`, `--udp`, or a profile)</sub>

Each stage's output feeds the next, and every stage logs the tool/command or
module it used, the hosts/ports/services it handled, its output location and
result count. Disabled stages are listed up front with the reason; a stage that
fails is marked `FAILED` and listed under **Assessment Gaps** rather than being
silently treated as done.

It runs with **zero external dependencies** (Python 3.8+ stdlib only).
`nmap`, `httpx`, `feroxbuster`, and `nuclei` are used automatically **if on the
PATH** for richer/faster results; otherwise pure-Python equivalents run (nuclei
is simply skipped).

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

The easiest way to run a good scan is a **profile** — a one-flag preset
(`quick` / `standard` / `deep` / `web`). Any explicit flag still overrides it.

```bash
# Profiles
python -m netassess scan --targets targets.txt --profile quick    # ~40 ports, fast triage
python -m netassess scan --targets targets.txt --profile standard # balanced default
python -m netassess scan --targets targets.txt --profile deep     # deep + content + nuclei
python -m netassess scan --targets targets.txt --profile web      # web ports + content + nuclei
python -m netassess scan --targets targets.txt --profile deep --no-nuclei   # deep, skip nuclei

# Full assessment from a file of IPs/CIDRs (defaults)
python -m netassess scan --targets targets.txt

# Already scanned with nmap? skip discovery and scan only the known ports
python -m netassess scan --targets targets.txt --skip-discovery --ports 22,80,443,8080

# Force the httpx HTTP backend; full TCP range; tuned performance
python -m netassess scan --targets targets.txt --http-tool httpx \
    --full-port-scan --concurrency 100 --rate 300 --timeout 2

# AI-assisted task ordering (needs ANTHROPIC_API_KEY; falls back safely)
python -m netassess scan --targets targets.txt --mode ai --ai-provider anthropic

# CVE correlation: offline by default; add live NVD enrichment or a custom DB
python -m netassess scan --targets targets.txt --cve-online
python -m netassess scan --targets targets.txt --cve-db my-cves.json --no-html

# Validate scope + test the authorization gate without touching the network
python -m netassess scope check --targets 10.0.0.0/24 --exclude 10.0.0.1 --test 10.0.0.5

# Regenerate a report from saved state
python -m netassess report --state out/state.json

# Diff two runs — what changed since last time? (great for re-tests / monitoring)
python -m netassess diff --old baseline/state.json --new latest/state.json --fail-on worse

# Continue testing: build a prioritized phase-2 plan from a finished scan
python -m netassess nextphase --state out/state.json --output phase2
```

### Key options

| Flag | Meaning |
|---|---|
| `--targets` | file path, or comma list of IPs/CIDRs (required) |
| `--profile` | preset bundle: `quick` · `standard` (default) · `deep` · `web`; explicit flags override |
| `--exclude` | file/comma IPs/CIDRs to exclude (always wins) |
| `--mode` | `deterministic` (default) · `ai` · `auto` |
| `--discovery` | host discovery: `auto` (nmap `-sn` if available + TCP fallback), `nmap`, or `tcp` (built-in) |
| `--skip-discovery` | treat every in-scope host as live (skip discovery) |
| `--ports` | explicit set, e.g. `22,80,443` or `1-1024` (overrides the default) |
| `--common-ports` | fast preset: 40 high-signal ports instead of top-1000 |
| `--full-port-scan` | scan all 65,535 TCP ports |
| `--udp` / `--udp-ports` | also scan common UDP ports (SNMP/NTP/DNS probes); or an explicit set |
| `--http-tool` | HTTP-probe backend: `auto` (httpx if installed, else built-in) · `httpx` · `builtin` |
| `--no-vhosts` | disable virtual-host discovery (on by default: probes TLS SAN/CN names) |
| `--deep` | deeper service detection (still non-destructive) |
| `--concurrency` / `--rate` / `--timeout` / `--retries` | performance & safety limits |
| `--content-discovery` | enumerate common web paths (admin/login/api/.env…) on HTTP services |
| `--content-tool` | `auto` (feroxbuster if installed, else built-in), `feroxbuster`, or `builtin` |
| `--content-quick` | use only the small curated list (~74 paths) instead of full SecLists |
| `--content-depth` / `--content-extensions` / `--content-thorough` | feroxbuster tuning |
| `--wordlist` | file of extra paths to append to the content-discovery list |
| `--nuclei` / `--nuclei-thorough` / `--nuclei-rate` | run nuclei (if installed) and tune it |
| `--no-nuclei` | force nuclei off even if a profile enabled it |
| `--no-smtp-relay-test` | disable the SMTP open-relay test (on by default; non-destructive) |
| `--no-validate` | disable the (non-destructive) validation layer |
| `--auth-config` | JSON of per-host key-based SSH creds for opt-in credentialed validation (read-only) |
| `--min-severity` | lowest severity shown in reports (default `info` — all shown) |
| `--all-findings` / `--include-noise` | include every finding / also show low-signal findings hidden by default |
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
Input → Scope Engine → Discovery → Asset Graph → Port Scanner → Service ID →
Protocol Probers → HTTP/TLS Analysis → Technology Detection → Virtual-host →
Default-login → Content Discovery → Endpoint/JS → Nuclei/UDP → Vuln + CVE/KEV →
Validation → Role/Anomaly → Report  (→ nextphase)
```

| Module | Responsibility |
|---|---|
| `scope.py` | Mandatory authorization gate, rate/concurrency policy, decision log |
| `config.py` | All tunables and policy |
| `profiles.py` | One-flag scan presets (`--profile quick/standard/deep/web`) |
| `state.py` | Persistent, queryable asset graph (JSON) |
| `discovery.py` | TCP-based live-host discovery (ICMP-independent) |
| `dns_recon.py` | Reverse DNS (PTR) — evidence only, not proof of ownership |
| `ports.py` | Pure-Python scanner + optional Nmap backend |
| `services.py` | Port+banner service identification; any-port HTTP heuristic |
| `probers/` | `ServiceProbe` interface: HTTP, TLS, SSH, SMTP, DNS, SMB, LDAP, RDP, VNC, rsync, DB, Generic |
| `techdetect.py` | HTTP technology fingerprinting with evidence/confidence |
| `vhost.py` | TLS SAN/CN virtual-host discovery (on by default) |
| `defaultlogin.py` | Default-login *exposure* checks for identified products (no creds sent) |
| `content_discovery.py` | Web path enumeration (built-in; distinct-404 aware) |
| `endpoints.py` | Endpoint/JS extraction (links, scripts, API paths) from web roots |
| `webfetch.py` | Minimal bounded GET shared by the analysis stages |
| `vuln/` | Safe, evidence-gated vulnerability heuristics + external-scanner hook |
| `cve/` | Offline CVE KB + version-range matching + NVD sync + CISA KEV/EPSS enrichment |
| `report_html.py` | Self-contained HTML report (inline CSS, severity-colored cards) |
| `diff.py` | Compare two `state.json` runs (new/closed ports, version changes, new/resolved findings) |
| `correlation.py` | IP→host→port→service→version→tech→finding chains |
| `prioritize.py` | Explainable, evidence-weighted risk scoring (drives `nextphase`) |
| `report.py` | Markdown + JSON report generator |
| `ai/` | Orchestrator: deterministic planner + optional LLM task-ranking |
| `adapters/` | External-tool adapters (nmap, httpx, feroxbuster, nuclei) returning structured data |

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

## UDP scanning & service probes

With `--udp`, netassess scans common UDP ports using **protocol-aware payloads**
(a blind UDP packet rarely gets a reply, so it sends a real DNS query, SNMP GET,
NTP request, etc.) and classifies each as open / open|filtered / closed. It then
runs read-only analysis on what answers:

- **SNMP (161)** — tries default community strings (`public`/`private`) with a
  `sysDescr` GET; a reply is flagged as information disclosure (high).
- **NTP (123)** — reads version/stratum and detects **mode-7 `monlist`**
  (CVE-2013-5211 amplification).
- **DNS/NetBIOS/SSDP/mDNS/…** — identified by their responses.

```bash
python -m netassess network scan --targets targets.txt --udp
python -m netassess network scan --targets targets.txt --udp --udp-ports 53,123,161
```

netassess also has an **LDAP probe** (TCP 389/636, runs automatically): an
anonymous simple bind + RootDSE query that flags anonymous-bind exposure and
**detects Active Directory Domain Controllers** from their naming contexts —
all read-only (no credentials, no writes). Everything above is scope-gated and
non-destructive.

## Virtual-host discovery (on by default; `--no-vhosts` to disable)

One IP often serves several web apps, each answering only to the right `Host`
header — an IP-only scan sees just the default one. netassess takes the
hostnames the server itself presents in its **TLS certificate** (SAN + CN,
already collected during TLS probing) and re-requests the **same in-scope
IP:port** with each as the `Host` header. Any that return a *different*
application than the default response are reported as distinct virtual hosts.
It runs by default; turn it off with `--no-vhosts`.

```bash
python -m netassess scan --targets targets.txt              # vhost discovery on
python -m netassess scan --targets targets.txt --no-vhosts  # off
```

**Scope-safe by design:** it never scans a new IP and needs no external OSINT —
it only varies the `Host` header against IPs already authorized and open, using
certificate data you already have. GET-only, scope-gated, non-destructive.

## nuclei integration (`--nuclei`, light by default)

With `--nuclei` (and nuclei installed), netassess runs ProjectDiscovery's
templates against the **web URLs it already discovered** — never a blind sweep —
using a profile tuned to stay light on targets:

- **targeted input** — only confirmed, in-scope URLs are tested;
- heavy template classes **excluded** (`dos,fuzzing,intrusive,brute-force,
  token-spray,headless`) — kept templates are mostly one request each;
- **rate/concurrency caps** (`-rl 30 -c 10 -bs 10`), short timeout, one retry;
- **`-no-interactsh`** (no external OOB callbacks) and `-duc`.

```bash
python -m netassess network scan --targets targets.txt --nuclei
python -m netassess network scan --targets targets.txt --nuclei --nuclei-rate 15
python -m netassess network scan --targets targets.txt --nuclei-thorough
```

Results are normalized into the `Finding` schema; **CVE templates carry their
CVE id, so KEV/EPSS enrichment applies to them too.** `--nuclei-thorough`
broadens the template set (still excluding dos/fuzzing/intrusive/headless) and
raises the rate. If nuclei isn't installed, the phase is skipped.
Install: <https://github.com/projectdiscovery/nuclei>.

## Content discovery (web path enumeration)

With `--content-discovery`, after HTTP services are found the tool requests a
wordlist of common paths on each one and reports which exist, so you can see the
reachable web attack surface.

* **Default wordlist:** the bundled **SecLists `common.txt`** (~4,700 paths) at
  [`data/common.txt`](data/common.txt). Bare paths are auto-graded by pattern
  (e.g. `.env`/`.git`/backups → high, `admin`/`api`/`login` → medium), and a
  curated list layers hand-tuned severities/wording on top.
* **`--content-quick`** uses only the small curated list (~74 high-signal paths)
  — much faster, ideal for a first pass or many hosts.
* **`--wordlist FILE`** appends your own paths.

```bash
# default: full SecLists common.txt (~4,700 paths), parallelized
python -m netassess network scan --targets targets.txt --content-discovery

# fast curated pass (~74 paths)
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
* `--filter-status 400,500,501,502,503` — drops bad-request / server-error noise
  **while keeping useful codes** (200/301/302/**401**/**403**/405 **and distinct
  404s**). 404 is kept because a resource can exist yet answer 404; `--auto-tune`
  collapses the generic not-found flood so only 404s that differ survive.
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

Reports stay readable without hiding anything:

* **Severity floor** — **all severities (info+) are shown by default**, so low
  and informational findings (e.g. *missing security headers*, *version
  disclosure*) are included. Raise the floor when you want to focus:
  `--min-severity medium` (or `high`, `critical`).
* **Cross-host aggregation** — the same issue seen on many hosts collapses into
  **one entry listing all affected assets** (e.g. "Missing HTTP security headers
  × 12 hosts") — so info/low findings never become per-host noise. This applies
  to every severity. Disable with `--no-aggregate`.

The full, unfiltered data is always in `report.json` and `state.json` too.

```bash
# default: everything (info+), aggregated by title across hosts
python -m netassess network scan --targets targets.txt

# focus the report on medium and above
python -m netassess network scan --targets targets.txt --min-severity medium

# one row per host instead of aggregating
python -m netassess network scan --targets targets.txt --no-aggregate
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

### Exploitation intelligence (CISA KEV + EPSS)

`netassess kev sync` downloads the **CISA Known Exploited Vulnerabilities**
catalog and **FIRST EPSS** scores (from CISA/FIRST, **not your targets**) into
`~/.netassess/kev.json`. Scans then enrich CVE findings offline:

- **KEV hit** → finding is flagged **"ACTIVELY EXPLOITED"**, severity floored to
  **High** (or **Critical** if used in ransomware), and it jumps to the top of
  prioritization.
- **EPSS** → each CVE gets its exploitation-probability score; high EPSS boosts
  priority.

```bash
netassess kev sync                       # ~1,700 KEV CVEs + ~380k EPSS scores
netassess network scan --targets targets.txt
```

This is the difference between "here are 30 CVEs" and "**these 2 are being
exploited right now — fix them first**." Zero target traffic.
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

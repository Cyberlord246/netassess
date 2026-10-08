# netassess — Usage & Options

Authorized, safe-by-default network attack-surface assessment. Runs on the
**Python 3.8+ standard library alone** (no required dependencies); optionally
accelerated by `nmap`, `httpx`, `feroxbuster`, and `nuclei` when installed.

> ⚠️ Only ever run this against systems you are **explicitly authorized** to
> assess. A mandatory scope engine gates every network operation and never
> auto-adds discovered hosts, but it cannot grant authorization you lack.

## Install / run

```bash
# from the repo root (the folder that contains the netassess/ package):
python3 -m netassess <command> [options]

# or install the console command:
pip3 install -e .        # then: netassess <command> [options]
```

## Commands

| Command | Purpose |
|---|---|
| `scan` (alias of `network scan`) | run a full assessment |
| `scope check` | validate/expand scope and test the authorization gate |
| `diff` | compare two `state.json` runs |
| `cve sync` | download the offline NVD CVE cache (no target traffic) |
| `kev sync` | download the CISA KEV + FIRST EPSS cache (no target traffic) |
| `report` | regenerate a report from a saved `state.json` |

---

## Quick start

```bash
netassess scan --targets targets.txt                 # full default assessment
netassess scan --targets 192.0.2.10,192.0.2.0/24     # inline IPs / CIDRs
```

`--targets` accepts a **file path** (one IP/CIDR per line, `#` comments allowed)
or a **comma-separated list** of IPs/CIDRs.

---

## Profiles — one-flag presets (`--profile`)

Don't want to hand-pick flags? Pick a profile. Each is a bundle of sensible
options; **any explicit flag still overrides the profile.**

| `--profile` | Bundles | Use when |
|---|---|---|
| `quick` | ~40 high-signal ports | First look, or a large scope to triage fast. |
| `standard` *(default)* | the built-in defaults | The balanced everyday scan (unchanged behavior). |
| `deep` | deep detection + content discovery + nuclei | A thorough audit of a handful of hosts. |
| `web` | common web ports + content discovery + nuclei | Web-app focus (vhost discovery is already on by default). |

```bash
netassess scan --targets targets.txt --profile quick      # fast triage
netassess scan --targets targets.txt --profile deep       # thorough
netassess scan --targets targets.txt --profile web        # web focus
# override any single option, e.g. keep deep but pin the ports:
netassess scan --targets targets.txt --profile deep --ports 22,80,443
```

The scan banner prints the active profile and exactly which options it enabled.

> Note: `--profile quick` shrinks the **port** set; `--content-quick` shrinks the
> content-discovery **wordlist**. They are independent — combine them for a fast
> ports *and* fast content sweep.

---

## `scan` — full option reference

### Targets & output
| Option | Meaning |
|---|---|
| `--targets TARGETS` | **required**. File path, or comma-separated IPs/CIDRs. |
| `--exclude EXCLUDE` | file/comma IPs/CIDRs to exclude (exclusions always win). |
| `--output OUTPUT` | output directory (default `netassess-out`). |
| `--profile {quick,standard,deep,web}` | preset bundle of options (default `standard`); explicit flags override it. |

### Ports & discovery
| Option | Meaning |
|---|---|
| `--ports PORTS` | explicit set, e.g. `22,80,443` or `1-1024` (overrides the default top-1000+). |
| `--common-ports` | fast preset: ~40 high-signal ports. |
| `--full-port-scan` | all 65535 TCP ports (slow — avoid at scale). |
| `--discovery {auto,nmap,tcp}` | host discovery method. `auto` = nmap `-sn` if present + TCP fallback; `nmap` = nmap only; `tcp` = built-in. |
| `--skip-discovery` | treat every in-scope host as live (skip host discovery). |
| `--skip-portscan` | skip the connect-scan; assume `--ports` open and probe directly (without `--ports`, limits to common web ports). Great after an external nmap. |
| `--nmap-import FILE` | import an nmap scan (`-oX` XML or `-oG` greppable): its open ports seed the run and its hosts join scope (implies `--skip-portscan`). `--targets` optional when given. |
| `--udp` | also scan common UDP ports (DNS/SNMP/NTP/NetBIOS/…) with protocol probes. |
| `--udp-ports UDP_PORTS` | UDP ports to scan, e.g. `53,123,161`. |

### Performance & timing
| Option | Meaning |
|---|---|
| `--concurrency N` | max simultaneous connections (default 50). |
| `--rate RATE` | max new connections/sec (token bucket, default 200). |
| `--timeout TIMEOUT` | per-connection timeout ceiling in seconds (default 3). |
| `--retries N` | extra attempts on transient failure. |
| `--no-adaptive-timeout` | use the full `--timeout` for every connection (disable RTT-based tightening). |
| `--no-adaptive-rate` | disable rate backoff on resource-exhaustion errors (backoff only triggers on overload like "too many open files", never on filtered ports). |
| `--resume` | continue a prior run: load `state.json` from the output dir and skip stages already completed. |

### HTTP / web
| Option | Meaning |
|---|---|
| `--http-tool {auto,httpx,builtin}` | HTTP-probe backend (default `auto`): use ProjectDiscovery `httpx` if installed (fast bulk fingerprint), else the built-in probe. |
| `--no-vhosts` | disable virtual-host discovery (it runs by default: probes TLS SAN/CN names as vhosts). |

### Content discovery (opt-in)
| Option | Meaning |
|---|---|
| `--content-discovery` | enumerate web paths (admin/login/api/.env…) on confirmed HTTP services — GET-only, scope-gated. Keeps 200/201/204, 301/302/307/308, 401/403, 405 **and distinct 404s** (a resource can exist yet answer 404); the generic not-found page is filtered against a 404 baseline so only 404s that differ surface. |
| `--content-tool {auto,feroxbuster,builtin}` | engine (default `auto`): feroxbuster if installed, else built-in. |
| `--content-quick` | use only the small curated path list (~74) instead of the bundled SecLists `common.txt` (~4,752). |
| `--wordlist WORDLIST` | file of extra paths (one per line) to append to the active corpus. |
| `--content-depth N` | feroxbuster recursion depth (default 2). |
| `--content-extensions LIST` | feroxbuster extensions, e.g. `php,bak,zip,sql`. |
| `--content-thorough` | feroxbuster: collect real extensions + probe for backups. |

### Vulnerability intel & validation
| Option | Meaning |
|---|---|
| `--no-cve` | disable CVE correlation. |
| `--nmap-vuln` | run nmap NSE vuln scripts (if nmap installed) as an extra CVE source on discovered ports; deduped against the offline KB. |
| `--nmap-vuln-script SCRIPT` | NSE script/category for `--nmap-vuln` (default `vulners` — needs the script + internet; `vuln` is bundled but broader/more active). |
| `--cve-online` | enrich CVE findings via NVD live during the scan (network, opt-in). |
| `--cve-db CVE_DB` | extra CVE JSON to merge into the offline KB. |
| `--no-validate` | disable the (non-destructive) validation layer. |
| `--auth-config FILE` | JSON of per-host key-based SSH creds for OPT-IN credentialed validation (read-only commands only; passwords never used). Example: `{"1.2.3.4":{"user":"audit","key":"~/.ssh/id","port":22}}`. |

### Other probes
| Option | Meaning |
|---|---|
| `--no-smtp-relay-test` | disable the SMTP open-relay test (default on; non-destructive, aborts before DATA — no mail sent). |
| `--nuclei` | run nuclei (if installed) against discovered URLs with a light profile. |
| `--nuclei-thorough` | broader nuclei template set (still excludes dos/fuzzing/intrusive/headless). |
| `--nuclei-rate N` | nuclei requests/sec cap (default 30). |
| `--no-nuclei` | force nuclei off even if a profile enabled it (e.g. `--profile deep --no-nuclei`). |
| `--deep` | deeper (still safe) probes. |

### Reporting
| Option | Meaning |
|---|---|
| `--no-html` | do not emit `report.html`. |
| `--csv` | also write `report.csv` (flat findings table). |
| `--sarif` | also write `report.sarif` (SARIF 2.1.0 for CI / code-scanning). |
| `--min-severity {info,low,medium,high,critical}` | lowest severity shown in reports. |
| `--all-findings` | include every finding (same as `--min-severity info`). |
| `--no-aggregate` | list findings per host instead of grouping the same issue across hosts. |
| `--include-noise` | also report low-signal findings hidden by default (missing security headers, version disclosure). |

### Orchestration & misc
| Option | Meaning |
|---|---|
| `--mode {deterministic,ai,auto}` | task-ordering mode (default deterministic). AI only *reorders* already scope-valid probe tasks; it never needs an API key — with no key it falls back to deterministic. |
| `--ai-provider {none,anthropic}` | AI orchestration provider (default none). |
| `--no-progress` | suppress the staged plan + live progress output. |

---

## Other commands

### `scope check`
```bash
netassess scope check --targets 10.0.0.0/24 --exclude 10.0.0.1 --test 10.0.0.5
```
| Option | Meaning |
|---|---|
| `--targets` | **required**. Same format as `scan`. |
| `--exclude` | IPs/CIDRs to exclude. |
| `--test IP[,IP]` | run specific IPs through the authorization gate and print the verdict. |

### `diff`
```bash
netassess diff --old baseline/state.json --new netassess-out/state.json --fail-on worse
```
| Option | Meaning |
|---|---|
| `--old` / `--new` | **required**. The two `state.json` files to compare. |
| `--output DIR` | write `diff.md` / `diff.json`. |
| `--fail-on {never,any,worse}` | exit non-zero on: any change, or only `worse` (new open ports / findings). Default `never`. |

### `cve sync` / `kev sync`
```bash
netassess cve sync                 # -> ~/.netassess/nvd.json  (talks to NVD, not targets)
netassess kev sync                 # -> ~/.netassess/kev.json  (talks to CISA/FIRST, not targets)
```
| Option | Meaning |
|---|---|
| `cve sync --products nginx,openssh` | limit the NVD sync to specific products (default: all fingerprinted products). |
| `--output PATH` | override the cache path. |

Tip: set `NVD_API_KEY` before `cve sync` for a much higher NVD rate limit. Both
caches are offline — scans then correlate and flag actively-exploited CVEs
without any target traffic.

### `nextphase` — continue testing from a finished scan
```bash
netassess nextphase --state netassess-out/state.json --top 25 --output phase2
```
Reads a phase-1 `state.json`, ranks assets with the priority engine, and writes:
- `phase2_targets.txt` — the highest-value hosts (already in authorized scope);
- `phase2.json` — per-host ports, score and the reasons each was prioritized;

then prints a ready-to-run deeper scan (`--skip-discovery --ports <known open
ports> --profile deep`) and the matching `diff` command against the baseline.

| Option | Meaning |
|---|---|
| `--state` | **required**. Phase-1 `state.json`. |
| `--output DIR` | where to write the plan files (default: the state file's directory). |
| `--top N` | number of top-prioritized assets to include (default 25). |

### `report`
```bash
netassess report --state netassess-out/state.json --output some-dir
```
Regenerates the Markdown/JSON report from a saved `state.json`.

---

## Recipes

```bash
# Fast triage of a large scope
netassess scan --targets targets.txt --profile quick

# Thorough audit of a few hosts (deep detection + content + nuclei)
netassess scan --targets targets.txt --profile deep

# Web-app focus, forcing the httpx backend and a fast content wordlist
netassess scan --targets targets.txt --profile web --http-tool httpx --content-quick

# Full network sweep of an IP range, including UDP
netassess scan --targets 10.0.0.0/24 --udp

# Populate offline exploitation intel once, then scan
netassess cve sync && netassess kev sync
netassess scan --targets targets.txt

# Monitor for change between runs (CI-friendly)
netassess diff --old baseline/state.json --new netassess-out/state.json --fail-on worse
```

---

## Pipeline stages & logging

Every scan runs these stages in order; each stage's output feeds the next. A
stage runs only if enabled — disabled stages are reported up front with the
reason they were skipped.

```
scope → live-host discovery → reverse DNS → port scan → service/version ID →
HTTP/HTTPS probing (all open ports, not just 80/443) → SSL/TLS analysis (every
https service, incl. non-standard ports) → technology detection → misconfig /
exposure checks → virtual-host discovery → default-login exposure →
content discovery → endpoint/JS analysis → nuclei → UDP → CVE correlation →
KEV/EPSS → vulnerability validation → role/anomaly analysis → report
```

**Status logging.** For every stage the run prints:
- the target(s) being processed, and per host the open ports found;
- each HTTP service detected as `scheme://ip:port -> HTTP <status> [title]`;
- the **tool and exact command** (`tool=nmap  cmd='nmap -sV …'`) or built-in
  **module** used;
- the output file/location (`state.json` after every stage; report paths at the
  end) and the number of findings/results;
- **why** a stage was skipped (e.g. `Nuclei templates: not requested`).

**Failures are reported, never silent.** If a stage raises, it is marked
`FAILED` with the error, recorded, and listed under **Assessment Gaps** in the
report; independent stages still run so one failure doesn't abort the scan.

Two always-on built-in stages (no flags needed):
- **Default-login exposure** — only where a product with known default
  credentials is *identified*, it GETs that product's login/admin path and flags
  an exposed interface for manual verification. It **never submits credentials**
  (no brute forcing); nuclei's `default-login` templates can test actively where
  permitted.
- **Endpoint/JS analysis** — parses each service's root document for links, JS
  references and API-looking paths, highlighting sensitive-looking endpoints.
  It also **fetches the referenced JS and scans for leaked secrets** (AWS/Google/
  GitHub/Slack/Stripe keys, private keys, JWTs — reported with redacted snippets)
  and computes the **Shodan-style favicon hash** for app fingerprinting.

## External tools (optional accelerators; built-in fallbacks otherwise)

| Tool | Speeds up / adds | Enable |
|---|---|---|
| `nmap` | host discovery + port/version scan | `apt install nmap` (used automatically) |
| `httpx` (ProjectDiscovery) | fast bulk HTTP fingerprinting | install the Go binary; `--http-tool auto` uses it automatically |
| `feroxbuster` | content discovery | `apt install feroxbuster`; `--content-tool auto` |
| `nuclei` | template checks | download release; `--nuclei` |

With **none** of these installed, netassess still runs the complete assessment on
pure Python (built-in TCP scanner, built-in HTTP probe, built-in content probe).

## Safety

Non-destructive by design: no exploitation, no credential brute-forcing, no
writes/persistence/DoS. Every network operation passes the scope engine; hosts
discovered mid-scan are never auto-added to scope. Findings are leads/validated
evidence — confirm before acting, and stay within authorized scope.

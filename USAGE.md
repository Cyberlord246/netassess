# netassess — Usage & Options

Authorized, safe-by-default network + web attack-surface assessment. Zero required
dependencies (Python 3.8+ stdlib); optionally accelerated by `nmap`, `httpx`,
`feroxbuster`, and `nuclei` when installed.

> Only ever run this against systems you are explicitly authorized to assess.

## Install / run

```bash
# from the repo root (the folder that contains the netassess/ package):
python3 -m netassess <command> [options]

# or install the console command:
pip3 install -e .        # then: netassess <command> [options]
# ensure ~/.local/bin is on PATH if the command isn't found
```

## Commands

| Command | Purpose |
|---|---|
| `scan` (alias of `network scan`) | run an assessment |
| `scope check` | validate/expand scope and test the authorization gate |
| `diff` | compare two `state.json` runs |
| `cve sync` | download the offline NVD CVE cache (no target traffic) |
| `kev sync` | download CISA KEV + FIRST EPSS cache (no target traffic) |
| `report` | regenerate a report from a saved `state.json` |

---

## Input decides the pipeline (profile)

netassess detects what you gave it and adapts. Explicit flags always override.

| You provide | Profile | Reverse DNS | Virtual-host discovery |
|---|---|---|---|
| domains / URLs (`domains.txt`) | **web** | off (names already known) | on (SNI+Host vhosts) |
| IPs / CIDRs (`10.0.0.0/24`) | **network** | on (name the IPs) | off |
| both | **mixed** | on | on |

The banner prints the detected profile, and the staged plan reflects it.

---

## `scan` options (full reference)

### Targets & scope
| Option | Meaning |
|---|---|
| `--targets TARGETS` | **required**. File path, or comma-separated IPs/CIDRs/hostnames/URLs. Hostnames are resolved to IPs (their IPs become scope); markdown `[x](url)` and `https://…/path` entries are cleaned. |
| `--exclude EXCLUDE` | file/comma IPs/CIDRs/hostnames to exclude (exclusions always win). |
| `--output OUTPUT` | output directory (default `netassess-out`). |

### Ports & scanning
| Option | Meaning |
|---|---|
| `--ports PORTS` | explicit set, e.g. `22,80,443` or `1-1024` (overrides the default top-1000+). |
| `--common-ports` | fast preset: ~40 high-signal ports. |
| `--full-port-scan` | all 65535 TCP ports (slow — avoid at scale). |
| `--skip-discovery` | treat every in-scope host as live (skip host discovery). |
| `--skip-portscan` | skip the scan; assume `--ports` open and probe directly. Without `--ports` it auto-limits to ~12 common web ports (so it can't explode). Probes fail gracefully on closed ports. |
| `--discovery {auto,nmap,tcp}` | host discovery method. `auto` = nmap `-sn` if present + TCP fallback; `nmap` = nmap only; `tcp` = built-in. |
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

### HTTP / web
| Option | Meaning |
|---|---|
| `--http-tool {auto,httpx,builtin}` | HTTP-probe backend. `auto` = ProjectDiscovery httpx if installed (fast bulk), else built-in. |
| `--no-vhosts` / `--vhosts` | force virtual-host discovery off / on (default follows the profile). |
| `--no-rdns` / `--rdns` | force reverse-DNS off / on (default follows the profile). |

### Content discovery (opt-in)
| Option | Meaning |
|---|---|
| `--content-discovery` | enumerate web paths (admin/login/api/.env…) on confirmed HTTP services — GET-only, scope-gated. |
| `--content-tool {auto,feroxbuster,builtin}` | engine: auto (feroxbuster if installed, else built-in) or force one. |
| `--content-quick` | use only the small curated path list (~70) instead of the bundled SecLists `common.txt` (~4,751). |
| `--wordlist WORDLIST` | file of extra paths (one per line) to add. |
| `--content-depth N` | feroxbuster recursion depth (default 2). |
| `--content-extensions LIST` | feroxbuster extensions, e.g. `php,bak,zip,sql`. |
| `--content-thorough` | feroxbuster: collect real extensions + probe for backups. |

### Vulnerability intel & validation
| Option | Meaning |
|---|---|
| `--no-cve` | disable CVE correlation. |
| `--cve-online` | enrich CVE findings via NVD (network, opt-in). |
| `--cve-db CVE_DB` | extra CVE JSON to merge into the KB. |
| `--no-validate` | disable the (non-destructive) validation layer. |
| `--auth-config FILE` | JSON of per-host key-based SSH creds for OPT-IN credentialed validation (read-only commands only; passwords never used). Example: `{"1.2.3.4":{"user":"audit","key":"~/.ssh/id","port":22}}`. |

### Other probes
| Option | Meaning |
|---|---|
| `--no-smtp-relay-test` | disable the SMTP open-relay test (default on; non-destructive, aborts before DATA — no mail sent). |
| `--nuclei` | run nuclei (if installed) against discovered URLs with a light profile. |
| `--nuclei-thorough` | broader nuclei template set (still excludes dos/fuzzing/intrusive/headless). |
| `--nuclei-rate N` | nuclei requests/sec cap (default 30). |
| `--deep` | deeper (still safe) probes. |

### Reporting
| Option | Meaning |
|---|---|
| `--no-html` | do not emit `report.html`. |
| `--min-severity {info,low,medium,high,critical}` | lowest severity shown (default medium). |
| `--all-findings` | include every finding (same as `--min-severity info`). |
| `--no-aggregate` | list findings per host instead of grouping the same issue across hosts. |
| `--include-noise` | also report low-signal findings hidden by default (missing security headers, version disclosure). |

### Misc
| Option | Meaning |
|---|---|
| `--mode {deterministic,ai,auto}` | task-ordering mode (default deterministic). |
| `--ai-provider {none,anthropic}` | AI orchestration provider. |
| `--no-progress` | suppress the staged plan + live progress output. |

---

## Recipes

### Web attack surface from a domain list (fast)
```bash
python3 -m netassess scan --targets domains.txt \
  --skip-discovery --skip-portscan --ports 80,443 \
  --content-discovery
```
Resolves domains → IPs (keeps Host/SNI), skips discovery + port scan, probes only
web ports, dedupes `:80`/`:443`, and produces the correlated web inventory.

### Full network sweep of an IP range
```bash
python3 -m netassess scan --targets 10.0.0.0/24 --udp
```
All default ports + UDP, reverse-DNS on, protocol probes, CVE/KEV, service inventory.

### Fast triage of a large scope
```bash
python3 -m netassess scan --targets targets.txt --common-ports --rate 500 --timeout 1.5
```

### Enrich with exploitation intel (offline, once)
```bash
python3 -m netassess cve sync      # NVD CVE cache
python3 -m netassess kev sync      # CISA KEV + EPSS
```

### Compare two runs (CI-friendly)
```bash
python3 -m netassess diff --old baseline/state.json --new latest/state.json \
  --fail-on worse
```

### Regenerate a report from saved state
```bash
python3 -m netassess report --state netassess-out/state.json
```

### Check scope without scanning
```bash
python3 -m netassess scope check --targets domains.txt --test 10.0.0.5
```

---

## External tools (optional accelerators; built-in fallbacks otherwise)

| Tool | Speeds up | Enable |
|---|---|---|
| `nmap` | host discovery + port scan | `apt install nmap` |
| `httpx` (ProjectDiscovery) | bulk HTTP probing | install the Go binary; `--http-tool auto` |
| `feroxbuster` | content discovery | `apt install feroxbuster`; `--content-tool auto` |
| `nuclei` | template checks | download release; `--nuclei` |

## Safety

Non-destructive by design: no exploitation, no credential brute-forcing, no
writes/persistence/DoS. Every network operation passes the scope engine; hosts
discovered mid-scan are never auto-added to scope. Findings are leads/validated
evidence — confirm before acting, and stay within authorized scope.

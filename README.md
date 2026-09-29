# netassess

[![CI](https://github.com/cyberlord246/netassess/actions/workflows/ci.yml/badge.svg)](https://github.com/cyberlord246/netassess/actions/workflows/ci.yml)

**Authorized, safe, modular network attack-surface assessment platform.**

Give it a list of IPs/CIDRs you are **explicitly authorized** to test; it builds
a structured attack-surface inventory and a report:

```
live hosts → reverse DNS → open ports → services/versions → protocol probes →
HTTP/TLS analysis → technology detection → safe vuln heuristics → CVE correlation →
content discovery → correlation → prioritization → report (MD / HTML / JSON)
```

Runs on the **Python 3.8+ standard library alone** (no required dependencies).
Uses `nmap` and `feroxbuster` automatically **if installed**, otherwise falls
back to built-in pure-Python equivalents.

> ⚠️ **Authorization is mandatory.** Only assess systems you own or have written
> permission to test. A mandatory scope engine gates every network operation and
> never auto-adds discovered hosts, but it cannot grant authorization you lack.

## Docker (zero host installs — everything bundled)

The image bundles netassess **plus `nmap`, `nuclei`, and `feroxbuster`**, with
nuclei templates baked in. You install nothing but Docker.

```bash
# build once
docker build -t netassess .

# run — targets.txt and reports live in the current directory (mounted at /work)
docker run --rm -v "$PWD:/work" netassess network scan --targets targets.txt --nuclei
```

Persist CVE/KEV caches (and templates) across runs with a named volume, then
populate them once:

```bash
docker run --rm -v "$PWD:/work" -v netassess-data:/root/.netassess netassess cve sync
docker run --rm -v "$PWD:/work" -v netassess-data:/root/.netassess netassess kev sync
docker run --rm -v "$PWD:/work" -v netassess-data:/root/.netassess netassess network scan --targets targets.txt
```

Or via Compose (handles the volume for you):

```bash
docker compose build
docker compose run --rm netassess network scan --targets targets.txt --nuclei
```

Runs on **macOS, Linux/Ubuntu, and Windows** (anywhere Docker runs). The build
selects native tool binaries for your architecture — **Intel/AMD (amd64) and
Apple Silicon (arm64)** — so a plain `docker build` just works. Both arches are
build-verified (arm64 via emulation).

All bundled tools — **netassess, nmap, nuclei (+templates), and feroxbuster** —
are present and verified on **both amd64 and arm64** (arm64 built & run via
emulation: feroxbuster 2.13.1, nuclei v3.11.1, nmap 7.95).

## Install (without Docker)

Install straight from GitHub (gives you a `netassess` command anywhere):

```bash
# with pipx (recommended for CLI tools)
pipx install "git+https://github.com/cyberlord246/netassess.git"

# or with pip
pip install "git+https://github.com/cyberlord246/netassess.git"
```

Private repo? Authenticate first (e.g. a GitHub personal access token):

```bash
pip install "git+https://TOKEN@github.com/cyberlord246/netassess.git"
```

Local/editable install for development:

```bash
git clone https://github.com/cyberlord246/netassess.git
cd netassess
pip install -e .
```

Optional extras: `nmap` (better service detection), `feroxbuster` (fast content
discovery), and `pip install "netassess[ai] @ git+..."` for the LLM mode.

## Usage

See **[USAGE.md](USAGE.md)** for the full command and option reference.

The easiest way to run a good scan is to pick a **profile** — a one-flag preset:

```bash
netassess scan --targets targets.txt --profile quick      # fast triage (~40 ports)
netassess scan --targets targets.txt --profile standard   # balanced default
netassess scan --targets targets.txt --profile deep       # deep detection + content + nuclei
netassess scan --targets targets.txt --profile web        # web ports + content + nuclei
```

Any explicit flag still overrides the profile (`--profile deep --ports 22,80,443`).
More examples:

```bash
netassess network scan --targets 192.0.2.10,192.0.2.0/24 --content-discovery
netassess scan --targets 203.0.113.5 --http-tool httpx --udp
netassess scope check --targets 10.0.0.0/24 --exclude 10.0.0.1
netassess diff --old baseline/state.json --new latest/state.json --fail-on worse
```

(Not installed as a command yet? Run it as a module from the repo root:
`python -m netassess scan ...`.)

## Highlights

- **Mandatory scope engine** — every active operation is authorized, rate- and
  concurrency-limited, and logged; discovered hosts are never auto-added.
- **Safe by default** — non-destructive checks only (no exploitation, no
  credential attacks, no writes).
- **Ports** — canonical Nmap **top-1000** by default (`--common-ports`,
  `--ports`, `--full-port-scan`).
- **Content discovery** — feroxbuster (auto, tuned for signal) or built-in probe,
  default SecLists `common.txt`; `--content-discovery`.
- **CVE correlation** — offline KB with version-range matching, optional live NVD.
- **Exploitation intel** — CISA KEV + FIRST EPSS enrichment flags actively-exploited CVEs.
- **Asset-role classification + anomaly detection** — infers each host's role and
  flags what doesn't fit (DB on a web host, exposed Docker/K8s/IPMI plane,
  over-consolidated host, DC running extra services). Pure analysis, always on.
- **Reports** — Markdown, self-contained HTML, and JSON; **all severities
  (info+) shown by default**, with same-title findings aggregated into one entry
  across hosts. Raise the floor with `--min-severity` (e.g. `medium`, `high`).
- **Diff mode** — compare two runs for new ports / new CVEs (great for monitoring).

Full documentation lives in **[`netassess/README.md`](netassess/README.md)**.

## Development

```bash
python -m netassess.tests.test_scope
python -m netassess.tests.test_cve
python -m netassess.tests.test_diff
python -m netassess.tests.test_ferox
```

## License

MIT — see [LICENSE](LICENSE).

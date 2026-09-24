# netassess

**Authorized, safe, modular network attack-surface assessment platform.**

Give it a list of IPs/CIDRs you are **explicitly authorized** to test; it builds
a structured attack-surface inventory and a report:

```
live hosts → reverse DNS → open ports → services/versions → protocol probes →
HTTP/TLS analysis → technology detection → safe vuln heuristics → CVE correlation →
content discovery → correlation → prioritization → report (MD / HTML / JSON)
```

Runs on the **Python 3.10+ standard library alone** (no required dependencies).
Uses `nmap` and `feroxbuster` automatically **if installed**, otherwise falls
back to built-in pure-Python equivalents.

> ⚠️ **Authorization is mandatory.** Only assess systems you own or have written
> permission to test. A mandatory scope engine gates every network operation and
> never auto-adds discovered hosts, but it cannot grant authorization you lack.

## Install

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

```bash
netassess network scan --targets targets.txt --mode auto
netassess network scan --targets 192.0.2.10,192.0.2.0/24 --content-discovery
netassess scope check --targets 10.0.0.0/24 --exclude 10.0.0.1
netassess diff --old baseline/state.json --new latest/state.json --fail-on worse
```

(Not installed as a command yet? Run it as a module from the repo root:
`python -m netassess network scan ...`.)

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
- **Reports** — Markdown, self-contained HTML, and JSON; findings filtered to
  medium+ and aggregated across hosts by default.
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

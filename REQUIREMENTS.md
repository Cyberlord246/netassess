# netassess — Prerequisites

## Required

- **Python 3.8+** — that's it. netassess runs on the **standard library alone**
  with no required third-party packages. Every stage has a pure-Python
  implementation, so a plain Python install performs a complete assessment.

```bash
python3 --version      # 3.8 or newer
```

## Optional external tools (recommended)

Each is **auto-detected** (via `PATH`) and, when present, makes a stage faster or
deeper. If one is missing, netassess falls back to its built-in equivalent — the
**only** exception is `nuclei`, whose stage is simply skipped when absent.

| Tool | Enables / speeds up | Fallback if missing |
|---|---|---|
| **nmap** | host discovery (`-sn`), port/version scan (`-sV`), and NSE CVE scripts (`--nmap-vuln`) | built-in TCP scanner + banner/`services.identify` |
| **httpx** (ProjectDiscovery) | fast bulk HTTP fingerprinting (`--http-tool`) | built-in HTTP probe |
| **feroxbuster** | content/directory discovery (`--content-discovery`, tech-aware `-x`) | built-in GET probe |
| **nuclei** (ProjectDiscovery) | template checks (`--nuclei`) | **skipped** (no fallback) |
| **whatweb** *or* **wappalyzer** | richer technology fingerprinting (`--tech-tool`) | built-in signature detection |
| **ssh** (OpenSSH client) | opt-in credentialed, read-only validation (`--auth-config`) | validation stays non-credentialed |

### Install the external tools

**Debian / Ubuntu / Kali**
```bash
sudo apt update
sudo apt install -y nmap feroxbuster whatweb openssh-client
# httpx + nuclei (ProjectDiscovery) — Go toolchain, or download release binaries:
go install github.com/projectdiscovery/httpx/cmd/httpx@latest
go install github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest
```

**macOS (Homebrew)**
```bash
brew install nmap feroxbuster whatweb httpx nuclei
```

**Windows**
- `nmap`: https://nmap.org/download.html
- `feroxbuster` / `httpx` / `nuclei`: download the release `.exe` and put it on `PATH`.
- `whatweb`: via WSL or Ruby.
- `ssh`: included with Windows 10/11 (OpenSSH client).

Not installed as a command? Run from the repo root with `python -m netassess …`.

## Optional Python extra — AI orchestration

Only needed for `--mode ai` / `--mode auto` with `--ai-provider anthropic`
(LLM task-ordering). It never changes coverage; without it the tool is fully
deterministic.

```bash
pip install "netassess[ai]"        # installs anthropic
export ANTHROPIC_API_KEY=sk-...    # required for the LLM to actually engage
```

## Optional data (fetched by netassess, no install)

These need **internet to populate** but talk to the data source, never your
targets, and are then used fully offline:

```bash
netassess cve sync     # offline NVD CVE cache -> ~/.netassess/nvd.json
netassess kev sync     # CISA KEV + FIRST EPSS -> ~/.netassess/kev.json
```

Larger content-discovery wordlists are optional too (the SecLists `common.txt`
is **bundled**); point `--wordlist` at any file, e.g. SecLists
`raft-large-directories.txt`.

## Zero-install alternative — Docker

The image bundles netassess **plus nmap, nuclei (+templates), and feroxbuster**;
you install nothing but Docker. See the README's Docker section.

## Verify what netassess sees

Any scan's banner / `[plan]` output reports which backend each stage will use
(e.g. `http probe : built-in (httpx not installed)`, `nuclei : NOT INSTALLED`),
so you can confirm your tooling at a glance. Quick check:

```bash
for t in nmap httpx feroxbuster nuclei whatweb wappalyzer ssh; do \
  command -v "$t" >/dev/null && echo "ok   $t" || echo "miss $t"; done
```

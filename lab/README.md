# netassess test lab

A small, **isolated, intentionally-vulnerable** environment for validating
netassess against real services (instead of loopback/mocks).

## Safety first
- Services here are deliberately weak (unauthenticated Redis, an exposed `.env`,
  an admin page). They run on an **`internal` Docker network** — **no host ports
  are published and there is no route to the internet.** Only the scanner
  container in this compose file can reach them.
- **Never** expose these services, and only run this on a host you control. This
  is for authorized self-testing of the scanner.

## What's in it
| Service | Address | Purpose |
|---|---|---|
| `web` (nginx) | 172.28.0.10 | exposes `/.env`, `/admin`, `robots.txt` → content discovery, HTTP checks |
| `web2` (apache) | 172.28.0.11 | different `Server` banner → tech detection / roles |
| `cache` (redis) | 172.28.0.12 | **unauthenticated** → high-severity exposure finding |

The scanner targets the whole lab subnet (`172.28.0.0/24`, see `targets.txt`).

## Run it
```bash
cd lab
docker compose up -d web web2 cache      # start the targets
docker compose run --rm scanner          # scan; report written to lab/out/
docker compose down -v                    # tear it all down
```
Or use the helper: `./run.sh` (Linux/macOS) or `./run.ps1` (Windows).

The report lands in **`lab/out/report.md` / `report.html` / `report.json`**.

## What you should see
- `cache` flagged **Unauthenticated Redis instance** (high).
- `web` content discovery hits: `/.env` (high), `/admin`, `robots.txt`.
- `web`/`web2` identified as **web-server** role; nginx/apache tech detection.
- A populated **Risk Ranking** section.

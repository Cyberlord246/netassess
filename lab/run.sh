#!/usr/bin/env bash
# Bring up the lab targets, run netassess against them, show where the report is.
set -e
cd "$(dirname "$0")"
docker compose up -d web web2 cache
echo "waiting for services to settle..."
sleep 3
docker compose run --rm scanner
echo "report: lab/out/report.md (and report.html / report.json)"
echo "tear down with: docker compose down -v"

# Bring up the lab targets, run netassess against them, show where the report is.
Set-Location $PSScriptRoot
docker compose up -d web web2 cache
Write-Host "waiting for services to settle..."
Start-Sleep -Seconds 3
docker compose run --rm scanner
Write-Host "report: lab/out/report.md (and report.html / report.json)"
Write-Host "tear down with: docker compose down -v"

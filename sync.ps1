# Push local changes to GitHub in one step (Windows / PowerShell).
# Usage:  ./sync.ps1 "your commit message"
param([string]$Message = "")

if (-not $Message) {
    $Message = "update: " + (Get-Date -Format "yyyy-MM-dd HH:mm")
}

git add -A
# Only commit if there is something staged.
git diff --cached --quiet
if ($LASTEXITCODE -ne 0) {
    git commit -m $Message
    git push
    Write-Host "Pushed: $Message"
} else {
    Write-Host "No changes to commit."
}

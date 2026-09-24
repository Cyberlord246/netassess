#!/usr/bin/env bash
# Push local changes to GitHub in one step (macOS / Linux / Git Bash).
# Usage:  ./sync.sh "your commit message"
set -e
MSG="${1:-update: $(date '+%Y-%m-%d %H:%M')}"

git add -A
if git diff --cached --quiet; then
    echo "No changes to commit."
else
    git commit -m "$MSG"
    git push
    echo "Pushed: $MSG"
fi

#!/usr/bin/env bash
# One-time setup: create a global `netassess` command (no pip/Docker needed).
# Usage:  bash install.sh   then open a new terminal and run:  netassess ...
set -e
REPO="$(cd "$(dirname "$0")" && pwd)"
mkdir -p "$HOME/.local/bin"
cat > "$HOME/.local/bin/netassess" <<EOF
#!/usr/bin/env bash
exec env PYTHONPATH="$REPO" python3 -m netassess "\$@"
EOF
chmod +x "$HOME/.local/bin/netassess"
case ":$PATH:" in
  *":$HOME/.local/bin:"*) ;;
  *) echo 'export PATH="$HOME/.local/bin:$PATH"' >> "$HOME/.bashrc" ;;
esac
echo "Done. Open a NEW terminal (or run: source ~/.bashrc), then:"
echo "  netassess network scan --targets targets.txt"

#!/bin/zsh
# Install/refresh the launchd service for the Claude Telegram bridge.
set -e
DIR="$(cd "$(dirname "$0")" && pwd)"
PLIST=~/Library/LaunchAgents/com.beepboop2025.claude-telegram-bridge.plist

chmod 600 "$DIR/config.json"
python3 "$DIR/bridge.py" --check || {
  echo "Fix config.json first (token / ids), then re-run ./setup.sh"; exit 1; }

cp "$DIR/com.beepboop2025.claude-telegram-bridge.plist" "$PLIST"
launchctl unload "$PLIST" 2>/dev/null || true
launchctl load "$PLIST"
echo "✅ bridge loaded. Logs: tail -f $DIR/bridge.log"

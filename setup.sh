#!/bin/zsh
# Install/refresh the launchd service for the Claude Telegram bridge.
#
# The plist is GENERATED here rather than committed, so the repo carries no
# absolute home path or account name. Override BRIDGE_LABEL to install under
# a different launchd label.
set -e
DIR="$(cd "$(dirname "$0")" && pwd)"
LABEL="${BRIDGE_LABEL:-com.beepboop2025.claude-telegram-bridge}"
PLIST="$HOME/Library/LaunchAgents/${LABEL}.plist"

chmod 600 "$DIR/config.json"
python3 "$DIR/bridge.py" --check || {
  echo "Fix config.json first (token / ids), then re-run ./setup.sh"; exit 1; }

sed -e "s|__LABEL__|${LABEL}|g" \
    -e "s|__DIR__|${DIR}|g" \
    -e "s|__HOME__|${HOME}|g" \
    "$DIR/launchd.plist.template" > "$PLIST"

launchctl unload "$PLIST" 2>/dev/null || true
launchctl load "$PLIST"
echo "✅ bridge loaded as ${LABEL}. Logs: tail -f $DIR/bridge.log"

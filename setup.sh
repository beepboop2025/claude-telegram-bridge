#!/bin/zsh
# Install/refresh the launchd service for the Claude Telegram bridge.
#
# The plist is GENERATED here rather than committed, so the repo carries no
# absolute home path or account name. Override BRIDGE_LABEL to install under
# a different launchd label.
set -euo pipefail
DIR="${0:A:h}"
LABEL="${BRIDGE_LABEL:-com.beepboop2025.claude-telegram-bridge}"
[[ "$LABEL" =~ '^[A-Za-z0-9.-]+$' ]] || {
  print -u2 "BRIDGE_LABEL may contain only letters, digits, dots, and hyphens"
  exit 1
}
PYTHON="${BRIDGE_PYTHON:-$(command -v python3)}"
[[ "$PYTHON" == /* && -x "$PYTHON" ]] || {
  print -u2 "BRIDGE_PYTHON must be an absolute executable path"
  exit 1
}
PLIST_DIR="$HOME/Library/LaunchAgents"
PLIST="$PLIST_DIR/${LABEL}.plist"
CONFIG="$DIR/config.json"

[[ -f "$CONFIG" && ! -L "$CONFIG" ]] || {
  print -u2 "config.json must be a regular file, not a symlink"
  exit 1
}
owner_uid="$(id -u)"
for private_file in "$CONFIG" "$DIR/state.json" "$DIR/bridge.log" \
                    "$DIR/bridge.log.1" "$DIR/launchd.out.log" \
                    "$DIR/launchd.err.log" "$DIR/.mcp-allowed.json"; do
  if [[ -e "$private_file" ]]; then
    [[ -f "$private_file" && ! -L "$private_file" ]] || {
      print -u2 "unsafe private bridge file: $private_file"
      exit 1
    }
    [[ "$(stat -f '%u:%l' "$private_file")" == "$owner_uid:1" ]] || {
      print -u2 "private bridge files must be owner-held and unlinked: $private_file"
      exit 1
    }
    chmod 600 "$private_file"
  fi
done

"$PYTHON" "$DIR/bridge.py" --check || {
  print -u2 "Fix config.json first (token / ids), then re-run ./setup.sh"
  exit 1
}

install -d -m 0755 "$PLIST_DIR"
[[ ! -L "$PLIST" ]] || {
  print -u2 "refusing symlinked LaunchAgent: $PLIST"
  exit 1
}
temporary="$(mktemp "$PLIST_DIR/.${LABEL}.plist.XXXXXX")"
trap 'rm -f "$temporary"' EXIT HUP INT TERM
"$PYTHON" "$DIR/bridge.py" --render-launchd \
  "$DIR/launchd.plist.template" "$temporary" "$LABEL" "$PYTHON" \
  "$DIR" "$HOME"
plutil -lint "$temporary"
chmod 0644 "$temporary"
mv -f "$temporary" "$PLIST"
trap - EXIT HUP INT TERM

domain="gui/$(id -u)"
launchctl bootout "$domain" "$PLIST" 2>/dev/null || true
launchctl bootstrap "$domain" "$PLIST"
print "✅ bridge loaded as ${LABEL}. Logs: tail -f $DIR/bridge.log"

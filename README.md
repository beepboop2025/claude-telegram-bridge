# claude-telegram-bridge (v4)

Use Claude Code on this Mac from Telegram, anywhere. Messages you send to
your private bot run headless Claude Code (`claude -p`, full permissions)
in a chosen repo; results come back to the chat. Sessions resume across
messages, so "fix the test" then "now commit and push" works.

v3: everything v2 had (streaming progress, non-blocking worker, queueing,
file transfer, model override) plus: tap-to-stop button on the progress
message, tap-to-switch /repos and /model keyboards, results rendered as
Telegram HTML with long outputs attached as .md files, process-group kill
for /stop (Bash children die too, SIGTERM then SIGKILL), 429 retry so
messages stop vanishing, voice-note capture, /cost daily spend ledger,
and git branch + dirty count in /status.

v4: **two engines** — Claude Code and Kimi Code (`/engine`, tap to pick;
kimi continues per-directory via `-c`; a lapsed Kimi membership is
reported with a renew hint). **Model picker includes Fable 5**
(`claude-fable-5`) alongside opus/sonnet/haiku. **`/attach`** continues
the most recent Claude session in the current directory — start work in
the terminal, keep going from your phone. Elapsed-time ticker keeps the
progress clock live during long silent tool calls.

Stdlib-only Python, long polling (no ports, no webhook, works behind NAT),
IPv4-forced (this network black-holes some IPv6).

## One-time setup

1. In Telegram, talk to **@BotFather** → `/newbot` → pick a name and a
   username → copy the token.
2. Paste the token into `config.json` (`bot_token`).
3. `./setup.sh` — starts the bridge in setup mode.
4. Message your new bot anything; it replies with your numeric user id.
5. Put that id in `allowed_user_ids` in `config.json`, run `./setup.sh`
   again. Done.

## Commands (in the Telegram chat)

| command | effect |
|---|---|
| *(any text)* | goes to Claude Code in the current cwd; progress streams live |
| *(photo/doc/voice + caption)* | file saved to `~/Downloads/telegram-bridge/`, caption becomes the prompt |
| `/stop` (or tap 🛑) | kill the current run (whole process tree) and clear the queue |
| `/repo LiquiLens` | switch to `~/dev/LiquiLens` (fresh session) |
| `/repos` | tap-to-switch repo buttons |
| `/cost` | today + 7-day Claude spend |
| `/cd <path>` | switch to any directory |
| `/new` | fresh Claude session |
| `/model` | tap-to-pick model: **fable 5** / opus / sonnet / haiku (`/model haiku` also works) |
| `/engine` | tap to pick 🤖 claude or 🌙 kimi |
| `/attach` | continue the latest Claude session in this cwd (terminal handoff) |
| `/get <path>` | send a file from the Mac to the chat (≤50MB) |
| `/sh git status` | raw shell command, no Claude |
| `/log 50` | tail the bridge log |
| `/status` | busy/idle, cwd, session, model, queue, uptime |

Messages sent while Claude is busy are queued and run in order. All
commands answer instantly even mid-run (per-chat worker thread; the
Telegram poll loop never blocks on Claude).

## Ops

- Service: `~/Library/LaunchAgents/com.beepboop2025.claude-telegram-bridge.plist`
  (launchd, `KeepAlive`, survives reboots; wrapped in `caffeinate -si` so
  the Mac stays awake while the bridge runs — keep the lid open).
- Logs: `bridge.log` (activity), `launchd.err.log` (crashes).
- Stop: `launchctl unload ~/Library/LaunchAgents/com.beepboop2025.claude-telegram-bridge.plist`
- Health check: `python3 bridge.py --check`

## Security model

- Claude runs with `bypassPermissions` — whoever reaches it has full
  control of this Mac. The ONLY gate is `allowed_user_ids`: messages from
  any other Telegram account are logged and dropped (in setup mode, i.e.
  empty whitelist, the bridge only echoes user ids and executes nothing).
- Therefore: never share the bot token or add ids you don't own; treat
  `config.json` like a password (chmod 600, gitignored).
- If the token ever leaks: @BotFather → `/revoke`, paste the new token,
  `./setup.sh`.

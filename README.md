# claude-telegram-bridge (v7)

Use Claude, Codex, Kimi, Cursor, and Grok on this Mac from Telegram or
Nicegram, anywhere. The same private bot is the only Telegram poller.
Terminal LLMs and Mission Control attach through `ll-hub` so they never
steal `getUpdates`. Results come back to the chat both clients already
show. Sessions resume across messages, so "fix the test" then "now
commit and push" works.

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

v5: **three engines** — Claude Code, OpenAI Codex, and Kimi Code. The Codex
engine uses official `codex exec --json` automation, resumes per-chat sessions,
and runs with `workspace-write` sandboxing rooted at the selected Git repository.
For remote safety it asks the CLI to ignore custom user configuration by
default; interactive Codex desktop tasks keep their normal integrations.

v6: **current Telegram and CLI surfaces**. Telegram Bot API 10.2 private-chat
topics now have separate queues, repositories, and engine sessions. Claude and
Codex prompts are sent over stdin instead of process arguments. Codex also
ignores repository rules by default for this remote-control surface, while
Claude loads project settings only and keeps a strict MCP allow-list. API
responses and file transfers are bounded, config and state JSON are strict,
and credential-bearing local artifacts are atomically stored as owner-only
files. The launchd installer now validates and atomically replaces its plist.

v7: **one hub, many clients**. Cursor (`agent -p`) and Grok (`grok --single`)
are optional engines. `ll-hub` is a local Unix-socket CLI. Mission Control
reads `health.json` only. `setMyCommands` and a webhook check keep Telegram
and Nicegram on the same bot. A second poller still exits on 409.

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
| *(any text)* | goes to the selected engine in the current cwd; progress streams live |
| *(photo/doc/voice + caption)* | file saved to `~/Downloads/telegram-bridge/`, caption becomes the prompt |
| `/stop` (or tap 🛑) | kill the current run (whole process tree) and clear the queue |
| `/repo LiquiLens` | switch to `~/dev/LiquiLens` (fresh session) |
| `/repos` | tap-to-switch repo buttons |
| `/cost` | today + 7-day Claude spend |
| `/cd <path>` | switch to any directory |
| `/new` | fresh Claude session |
| `/model` | tap-to-pick model: **fable 5** / opus / sonnet / haiku (`/model haiku` also works) |
| `/engine` | tap to pick claude, codex, kimi, cursor, or grok |
| `/attach` | continue the latest Claude or Cursor session in this cwd |
| `/clients` | how Telegram, Nicegram, and `ll-hub` share this bot |
| `/get <path>` | send a file from the Mac to the chat (≤50MB) |
| `/sh git status` | raw shell command, no engine |
| `/log 50` | tail the bridge log |
| `/status` | busy/idle, cwd, session, model, queue, uptime |

## Local CLI and Nicegram

Nicegram is a Telegram client. There is no second bot API. Message the same
bot from either app. Private topics and the command menu appear in both.

On this Mac, do not start another poller. Use the local CLI:

```bash
ll-hub status
ll-hub engine cursor
ll-hub repo LiquiLens
ll-hub send "fix the test"
ll-hub stop
```

`ll-hub send` enqueues on the same worker Telegram uses. The result lands
in the private chat, so it is visible in Telegram and Nicegram.

Mission Control observes
`~/Library/Application Support/liquilens-agent-hub/health.json`.
It does not read the bot token and cannot enqueue work. The bridge binds and
listens on the owner-only socket before it publishes healthy startup. An unsafe
leftover path, permission/bind failure, or already-active Hub makes startup fail
closed; `health.json` reports `socket: false` if the listener later stops.

Messages sent while an engine is busy are queued and run in order. Each
private-chat topic has an independent worker, repository, and resumable
session. Commands answer instantly even mid-run; the Telegram poll loop never
blocks on an engine.

## Ops

- Service: `~/Library/LaunchAgents/com.beepboop2025.claude-telegram-bridge.plist`
  by default, generated by `./setup.sh`. It uses launchd `KeepAlive`, survives
  reboots, and is wrapped in `caffeinate -si`; keep the lid open.
- Logs: `bridge.log` (activity), `launchd.err.log` (crashes).
- Refresh: `./setup.sh`
- Stop: `launchctl bootout "gui/$(id -u)" ~/Library/LaunchAgents/com.beepboop2025.claude-telegram-bridge.plist`
- Health check: `python3 bridge.py --check`
- Codex binary: an explicit `codex_bin` in `config.json` wins. Otherwise the
  bridge follows the standalone install's stable `~/.local/bin/codex` symlink,
  then looks on `PATH`; `--check` fails loudly if neither is executable.

## Security model

- Claude runs with `bypassPermissions` — whoever reaches it has full
  control of this Mac. The ONLY gate is `allowed_user_ids`: messages from
  any other Telegram account are logged and dropped (in setup mode, i.e.
  empty whitelist, the bridge only echoes user ids and executes nothing).
- Therefore: never share the bot token or add ids you don't own; treat
  `config.json`, `state.json`, `bridge.log`, inbox, and outbox as private.
  The bridge and installer enforce modes 0600 for files and 0700 for
  directories, reject final symlinks, and replace state atomically.
- If the token ever leaks: @BotFather → `/revoke`, paste the new token,
  `./setup.sh`.

### Indirect prompt injection

The whitelist stops other people from *messaging* the bridge. It does
nothing about text the agent *reads* — a web page, a repo, a forwarded
PDF — which can carry instructions of its own. Four narrowings, all
covered by `python3 test_bridge.py`:

- **Tool surface.** Runs launch with `--mcp-config` + `--strict-mcp-config`
  against an allow-list (`mcp_allow` in `config.json`, names matched
  against `~/.claude.json`). Deny by default. Measured 2026-08-03: an
  unrestricted run saw 14 MCP servers, among them `safari` (the owner's
  logged-in browser plus clipboard), `playwright`, `MCP_DOCKER`, Gmail,
  Drive, Slack and Notion. The default product allow-list is `seiche`,
  `liquilens`, `undertow`, and `groundcheck`. Both flags are required;
  `--mcp-config` alone merges with user scope and changes nothing.
- **Claude settings.** Bridge runs use `--setting-sources project` and
  `--no-chrome`. Repository-owned settings remain available, while user and
  local hooks, plugins, and browser control do not enter a full-permission
  remote session.
- **Codex surface.** Telegram Codex runs use `--sandbox workspace-write` and
  `--ignore-user-config` plus `--ignore-rules` by default. Writes are limited
  to the selected
  repository, but filesystem reads may extend beyond it; the secret scanner is
  defense in depth, not a privacy boundary. Custom global MCP configuration is
  not loaded. Built-in and account-level capabilities remain governed by Codex.
  Set
  `codex_ignore_user_config` to `false` only after accepting the wider
  remote-control risk.
- **Prompt transport.** Claude and Codex receive prompts on stdin, so chat
  text is absent from process listings and cannot become a CLI option. Kimi's
  CLI requires a prompt option; the bridge supplies it as one `--prompt=value`
  argument so a leading dash cannot add flags.
- **Protocol bounds.** Telegram JSON rejects duplicate keys and nonfinite
  values. API and error bodies, downloads, uploads, `/log`, config, and state
  all have explicit size limits. A corrupt state file stops startup instead
  of silently resetting the polling offset and replaying updates.
- **Outbound content.** `deliver_result` scans for credential shapes and
  refuses, naming the matched class and never the value; the check runs
  before the >3500-char auto-attach writes its `.md`. Sibling surfaces —
  the progress ticker, `/sh`, `/log` — redact instead of refusing, so
  routine work keeps working.
- **Outbound paths.** `is_sensitive` still guards `/get` and `_send_file`.
- **Forwarded messages.** A forward's text was written by someone else, so
  it is never auto-run as a prompt or a command. The file is still saved;
  acting on it takes `/file <instruction>` or a tap of the run button.
  The guard sits above the command dispatch on purpose.

Not covered: `/sh` is a full shell by design, and the Kimi engine has no
per-invocation MCP flag (it loads only `openclaw`).

Optional security controls in `config.json` retain these v7 defaults:

```json
{
  "mcp_allow": ["seiche", "liquilens", "undertow", "groundcheck"],
  "claude_setting_sources": "project",
  "codex_ignore_user_config": true,
  "codex_ignore_rules": true,
  "codex_sandbox": "workspace-write",
  "cursor_force": true,
  "cursor_bin": "~/.local/bin/agent",
  "grok_bin": "~/.local/bin/grok"
}
```

Cursor MCP servers are not auto-approved. Set `cursor_force` to false only
if you accept hung approval prompts on the phone. If `grok` lives on PATH
instead of `~/.local/bin/grok`, the bridge picks that up at startup.

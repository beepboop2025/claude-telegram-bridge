#!/usr/bin/env python3
"""Telegram -> Claude / Codex / Kimi / Cursor / Grok bridge v7.

v4: model picker includes Fable 5 (claude-fable-5); second engine, Kimi
Code (/engine, per-directory -c continuity, errors surfaced with a renew
hint); /attach continues the latest Claude session in the cwd (terminal
handoff); elapsed-time ticker keeps the progress clock moving during
long silent tool calls.

v5: third engine — OpenAI Codex (`codex exec`, resumable JSONL sessions).
Codex runs with `workspace-write` sandboxing rooted at the selected Git
repository and asks the CLI to ignore custom user configuration by default.
That limits writes, but Codex may still read outside the repository; outbound
secret scanning remains a second line of defense, not a privacy boundary.

v6: Telegram Bot API private-chat topics have isolated queues and sessions;
prompts reach Claude and Codex over stdin; current CLI isolation flags are
verified before launch; JSON, HTTP bodies and file transfers are bounded;
and every local credential-bearing artifact is written atomically as 0600.

v7: one Telegram poller remains the only getUpdates owner. A mode-0600
Unix socket and `ll-hub` CLI let terminal, Cursor, Codex, and Grok share
that same worker. Cursor (`agent -p`) and Grok (`grok --single`) are
optional engines. setMyCommands and a webhook check keep Telegram and
Nicegram on the same bot. Mission Control reads health.json only.

Runs on this Mac. Polls Telegram (getUpdates long polling, outbound HTTPS
only, works behind NAT). Messages from the whitelisted user are fed to
the selected engine; replies come back to the same chat.

v3 over v2:
- process-group kill for /stop (children die too), SIGTERM -> SIGKILL
  escalation, timeout distinguished from user stop
- inline keyboards: stop button on the live progress message, tap-to-switch
  /repos, tap-to-pick /model
- results rendered as Telegram HTML (code blocks/bold survive); long
  outputs auto-attached as a .md document instead of chopped chunks
- 429 rate-limit retry (no more silently dropped messages)
- file/voice uploads handled off the poll loop; voice notes saved too
- per-day cost ledger (/cost), git branch + dirty count in /status
- fixed: /stop now works during a stale-session retry

Stdlib only. No pip installs.
"""

import html
import json
import os
import plistlib
import queue
import re
import shutil
import signal
import subprocess
import socket
import stat
import sys
import tempfile
import threading
import time
import urllib.error
import urllib.parse
import urllib.request
import uuid
from collections import deque

import hub_local

BASE_DIR = os.path.dirname(os.path.abspath(__file__))
CONFIG_PATH = os.path.join(BASE_DIR, "config.json")
STATE_PATH = os.path.join(BASE_DIR, "state.json")
LOG_PATH = os.path.join(BASE_DIR, "bridge.log")
INBOX_DIR = os.path.expanduser("~/Downloads/telegram-bridge")
OUTBOX_DIR = os.path.join(BASE_DIR, "outbox")

MAX_MSG = 4000          # Telegram hard cap is 4096; leave headroom
LONG_RESULT = 3500      # above this, attach full output as a file
EDIT_INTERVAL = 3.0     # min seconds between progress edits (rate limits)
PROGRESS_ACTIONS = 8    # how many recent actions to show while running
KILL_GRACE = 8          # seconds between SIGTERM and SIGKILL
MAX_API_RESPONSE = 8 * 1024 * 1024
MAX_ERROR_RESPONSE = 64 * 1024
MAX_DOWNLOAD = 20 * 1024 * 1024
MAX_UPLOAD = 50 * 1024 * 1024
MAX_LOCAL_JSON = 8 * 1024 * 1024
PRIVATE_FILE_MODE = 0o600
PRIVATE_DIR_MODE = 0o700

MODELS = ["fable", "opus", "sonnet", "haiku", "default"]
MODEL_IDS = {"fable": "claude-fable-5"}   # friendly name -> CLI model id
CONTINUE = "__continue__"                 # session sentinel for /attach


# ---------------------------------------------------------------- utilities

_log_lock = threading.Lock()


def strict_json_loads(raw, label="JSON"):
    """Parse a finite JSON document and reject duplicate object keys."""
    if isinstance(raw, bytes):
        raw = raw.decode("utf-8", errors="strict")

    def unique_object(pairs):
        value = {}
        for key, item in pairs:
            if key in value:
                raise ValueError(f"duplicate key in {label}: {key}")
            value[key] = item
        return value

    def reject_constant(value):
        raise ValueError(f"nonfinite value in {label}: {value}")

    return json.loads(raw, object_pairs_hook=unique_object,
                      parse_constant=reject_constant)


def read_bounded(response, limit, label):
    """Read one HTTP response without trusting its declared length."""
    declared = response.headers.get("Content-Length")
    if declared is not None:
        if not declared.isdigit() or int(declared) > limit:
            raise ValueError(f"{label} exceeds {limit} bytes")
    body = response.read(limit + 1)
    if len(body) > limit:
        raise ValueError(f"{label} exceeds {limit} bytes")
    return body


def _owner_regular(info, label):
    if (not stat.S_ISREG(info.st_mode) or info.st_nlink != 1
            or info.st_uid != os.geteuid()):
        raise OSError(f"unsafe private file metadata: {label}")


def read_private(path, limit=MAX_LOCAL_JSON, missing=None):
    """Read an owner-only regular file without following its final symlink."""
    flags = os.O_RDONLY | getattr(os, "O_CLOEXEC", 0)
    flags |= getattr(os, "O_NOFOLLOW", 0)
    try:
        fd = os.open(path, flags)
    except FileNotFoundError:
        if missing is not None:
            return missing
        raise
    try:
        info = os.fstat(fd)
        _owner_regular(info, path)
        if stat.S_IMODE(info.st_mode) != PRIVATE_FILE_MODE:
            os.fchmod(fd, PRIVATE_FILE_MODE)
        with os.fdopen(fd, "rb", closefd=False) as handle:
            body = handle.read(limit + 1)
        if len(body) > limit:
            raise OSError(f"private file exceeds {limit} bytes: {path}")
        return body
    finally:
        os.close(fd)


def atomic_private_write(path, body):
    """Replace one private file atomically and durably."""
    if isinstance(body, str):
        body = body.encode("utf-8")
    directory = os.path.dirname(path) or "."
    parent = os.lstat(directory)
    if (not stat.S_ISDIR(parent.st_mode) or stat.S_ISLNK(parent.st_mode)
            or parent.st_uid != os.geteuid()):
        raise OSError(f"unsafe private file directory: {directory}")
    fd, temporary = tempfile.mkstemp(
        prefix=f".{os.path.basename(path)}-", dir=directory)
    try:
        os.fchmod(fd, PRIVATE_FILE_MODE)
        with os.fdopen(fd, "wb", closefd=False) as handle:
            handle.write(body)
            handle.flush()
            os.fsync(fd)
        os.replace(temporary, path)
        directory_fd = os.open(directory, os.O_RDONLY | os.O_DIRECTORY)
        try:
            os.fsync(directory_fd)
        finally:
            os.close(directory_fd)
    finally:
        os.close(fd)
        try:
            os.unlink(temporary)
        except FileNotFoundError:
            pass


def ensure_private_dir(path):
    os.makedirs(path, mode=PRIVATE_DIR_MODE, exist_ok=True)
    info = os.lstat(path)
    if (not stat.S_ISDIR(info.st_mode) or stat.S_ISLNK(info.st_mode)
            or info.st_uid != os.geteuid()):
        raise OSError(f"unsafe private directory: {path}")
    if stat.S_IMODE(info.st_mode) != PRIVATE_DIR_MODE:
        os.chmod(path, PRIVATE_DIR_MODE)


def render_launchd_plist(template_path, output_path, label, python_path,
                         bridge_dir, home_dir):
    """Render one launchd plist without text substitution or array mutation."""
    if not re.fullmatch(r"[A-Za-z0-9.-]+", label):
        raise ValueError("unsafe launchd label")
    for name, value in (("python", python_path), ("bridge", bridge_dir),
                        ("home", home_dir)):
        if not os.path.isabs(value) or "\x00" in value:
            raise ValueError(f"{name} path must be absolute")
    with open(template_path, "rb") as handle:
        payload = plistlib.load(handle)
    payload["Label"] = label
    payload["ProgramArguments"] = [
        "/usr/bin/caffeinate", "-si", python_path,
        os.path.join(bridge_dir, "bridge.py"),
    ]
    payload["WorkingDirectory"] = bridge_dir
    payload["StandardOutPath"] = os.path.join(
        bridge_dir, "launchd.out.log")
    payload["StandardErrorPath"] = os.path.join(
        bridge_dir, "launchd.err.log")
    payload["EnvironmentVariables"] = {
        "PATH": (f"{home_dir}/.local/bin:/opt/homebrew/bin:/usr/local/bin:"
                 "/usr/bin:/bin:/usr/sbin:/sbin"),
        "HOME": home_dir,
    }
    flags = os.O_WRONLY | os.O_TRUNC | getattr(os, "O_CLOEXEC", 0)
    flags |= getattr(os, "O_NOFOLLOW", 0)
    fd = os.open(output_path, flags)
    try:
        _owner_regular(os.fstat(fd), output_path)
        os.fchmod(fd, PRIVATE_FILE_MODE)
        with os.fdopen(fd, "wb", closefd=False) as handle:
            plistlib.dump(payload, handle, sort_keys=False)
            handle.flush()
            os.fsync(fd)
    finally:
        os.close(fd)


def log(msg):
    line = f"[{time.strftime('%Y-%m-%d %H:%M:%S')}] {msg}"
    with _log_lock:
        try:
            print(line, flush=True)
        except OSError:
            # A full disk or a closed stdout used to raise out of log(), out of
            # get_updates(), and kill the process — launchd then respawned it
            # every 10s forever. Logging must never be able to stop the bridge.
            pass
        try:
            flags = os.O_WRONLY | os.O_APPEND | os.O_CREAT
            flags |= getattr(os, "O_CLOEXEC", 0)
            flags |= getattr(os, "O_NOFOLLOW", 0)
            fd = os.open(LOG_PATH, flags, PRIVATE_FILE_MODE)
            try:
                info = os.fstat(fd)
                _owner_regular(info, LOG_PATH)
                os.fchmod(fd, PRIVATE_FILE_MODE)
                os.write(fd, (line + "\n").encode("utf-8", errors="replace"))
                size = os.fstat(fd).st_size
            finally:
                os.close(fd)
            if size > 8 * 1024 * 1024:
                os.replace(LOG_PATH, LOG_PATH + ".1")
        except OSError:
            pass


# Credential-shaped paths refused for upload. This is not a sandbox — /sh
# is a full shell by design — it stops one mistyped command from putting a
# private key or a token onto Telegram's servers, where it cannot be recalled.
#
# Three gaps closed 2026-08-03 after an audit walked the real predicate over
# real paths on this machine: the login keychain, the shell histories and the
# whole ~/.claude tree (the memory corpus names the vault, the wallet master
# reference and every private project) were all ALLOWED, and a `/get` of any
# of them is one typo away.
_SENSITIVE_PARTS = ("/.ssh/", "/.gnupg/", "/.aws/", "/.kube/", "/.config/",
                    "/private_vault/", "/.hermes/", "/library/keychains/",
                    "/.claude/", "/.password-store/")
_SENSITIVE_NAMES = ("id_rsa", "id_ed25519", "id_ecdsa", "config.json",
                    "credentials", ".env", "known_hosts", ".zsh_history",
                    ".bash_history", ".python_history", ".npmrc", ".netrc",
                    ".pgpass", ".git-credentials", ".claude.json",
                    ".dev.vars")
_SENSITIVE_SUFFIX = (".pem", ".key", ".p12", ".pfx", ".session", ".env",
                     ".keychain-db", ".kdbx", ".ovpn", ".jks")


def is_sensitive(path):
    """True if this path looks like credential material.

    realpath, not abspath: abspath does not resolve symlinks, while the
    sender opens the resolved target, so a link inside any repo pointing at
    ~/.ssh/id_ed25519 passed the check and uploaded the key.
    """
    low = os.path.realpath(os.path.expanduser(path)).lower()
    name = os.path.basename(low)
    return (any(p in low for p in _SENSITIVE_PARTS)
            or name in _SENSITIVE_NAMES
            or name.startswith(".env")
            or low.endswith(_SENSITIVE_SUFFIX))


# Telegram marks forwards differently across Bot API versions: >= 7.0 sets
# forward_origin, older clients set forward_from / forward_from_chat /
# forward_sender_name / forward_date, and a channel post auto-relayed into a
# discussion group sets is_automatic_forward. Any of them means the text was
# authored by someone other than the owner, so treat the whole set as one.
_FORWARD_KEYS = ("forward_origin", "forward_from", "forward_from_chat",
                 "forward_sender_name", "forward_date", "forward_signature",
                 "is_automatic_forward")


def is_forwarded(msg):
    """True if this message carries text somebody else wrote."""
    return any(msg.get(k) for k in _FORWARD_KEYS)


# ------------------------------------------------------- MCP tool surface
#
# A headless `claude -p` inherits the USER-scope MCP servers from
# ~/.claude.json. On this Mac that set includes `safari` (drives the owner's
# logged-in browser and reads the system clipboard) and `MCP_DOCKER`. A bridge
# run is reachable from a public Telegram bot and starts with
# bypassPermissions, so any text the agent reads can steer it into those
# tools. That collides head-on with the standing rule that Claude never
# operates a logged-in session.
#
# So: deny by default. We name the servers we are willing to expose, copy
# their real definitions out of the user config (never re-typing whatever
# credentials live in their `env`), and hand claude --strict-mcp-config so
# nothing else can load. A server added to ~/.claude.json later is excluded
# until someone puts its name in `mcp_allow`.
USER_MCP_PATH = os.path.expanduser("~/.claude.json")
MCP_CONFIG_PATH = os.path.join(BASE_DIR, ".mcp-allowed.json")
MCP_ALLOW_DEFAULT = ["seiche", "liquilens", "undertow", "groundcheck"]
EMPTY_MCP = '{"mcpServers": {}}'


def select_mcp_servers(allow, user_config):
    """Intersect the allow-list with the user's real server definitions.

    Pure and total: unknown names are dropped, a malformed config yields an
    empty set. Never raises, because the caller is on the launch path.
    """
    servers = (user_config or {}).get("mcpServers")
    if not isinstance(servers, dict):
        return {}
    return {n: servers[n] for n in allow
            if isinstance(servers.get(n), dict)}


def write_mcp_config(allow):
    """Materialise the allowed-server config; return a path, or None.

    Returns None only if the file cannot be written, and the caller then
    falls back to an inline empty config. Either way --strict-mcp-config
    still goes on the command line: this narrows the tool surface, it can
    never widen it, and it can never stop a run from starting. A file rather
    than an inline JSON string because a server definition may carry an API
    key in `env`, and argv is world-readable via ps.
    """
    try:
        user_config = strict_json_loads(
            read_private(USER_MCP_PATH, missing=b"{}"), USER_MCP_PATH)
    except (OSError, TypeError, ValueError) as e:
        log(f"mcp: user config unreadable ({e.__class__.__name__}); "
            f"running with no MCP servers")
        user_config = {}
    chosen = select_mcp_servers(allow, user_config)
    try:
        payload = json.dumps({"mcpServers": chosen}, sort_keys=True,
                             separators=(",", ":")) + "\n"
        atomic_private_write(MCP_CONFIG_PATH, payload)
    except OSError as e:
        log(f"mcp: could not write {MCP_CONFIG_PATH} ({e}); "
            f"falling back to an inline empty config")
        return None
    return MCP_CONFIG_PATH


# ---------------------------------------------------------- secret scanning
#
# Output leaving this bridge lands on Telegram's servers and cannot be
# recalled. is_sensitive() guards paths; this guards CONTENT, which is the
# hole an injected agent actually walks through: it never has to name a
# credential file, it just has to read one and put the value in its answer.
#
# Matches are reported by CLASS only. The value is never logged, never echoed
# and never sent — printing it to explain the refusal would be the leak.
_SECRET_PATTERNS = [
    ("private-key-block",
     re.compile(r"-----BEGIN [A-Z0-9 ]*PRIVATE KEY-----")),
    ("openssh-private-key",
     re.compile(r"-----BEGIN OPENSSH PRIVATE KEY-----")),
    ("pgp-private-key",
     re.compile(r"-----BEGIN PGP PRIVATE KEY BLOCK-----")),
    ("aws-access-key-id",
     re.compile(r"\b(?:AKIA|ASIA|ABIA|ACCA|AIDA|AROA|ANPA|ANVA|AGPA)"
                r"[0-9A-Z]{16}\b")),
    ("telegram-bot-token",
     re.compile(r"\b\d{8,12}:AA[0-9A-Za-z_-]{30,}")),
    ("anthropic-or-openai-key",
     re.compile(r"\bsk-[0-9A-Za-z_-]{16,}")),
    ("github-token",
     re.compile(r"\b(?:ghp|gho|ghu|ghs|ghr)_[0-9A-Za-z]{20,}"
                r"|\bgithub_pat_[0-9A-Za-z_]{20,}")),
    ("slack-token",
     re.compile(r"\bxox[abporse]-[0-9A-Za-z-]{10,}")),
    ("google-api-key", re.compile(r"\bAIza[0-9A-Za-z_-]{35}\b")),
    ("stripe-key", re.compile(r"\b[rs]k_(?:live|test)_[0-9A-Za-z]{16,}")),
    ("jwt", re.compile(r"\beyJ[0-9A-Za-z_-]{8,}\.[0-9A-Za-z_-]{8,}"
                       r"\.[0-9A-Za-z_-]{8,}")),
]

# A high-entropy blob sitting on the right-hand side of a credential word.
# The assignment punctuation is required on purpose: "token" is an ordinary
# word in agent output ("2400 tokens used"), and matching mere adjacency
# refused honest results. This wants to look like KEY=<blob>.
# No \b around the keyword on purpose: the real-world spelling is
# ANTHROPIC_API_KEY=..., and a word boundary cannot fall between "C" and
# "API" because "_" is itself a word character. The length, entropy and
# placeholder filters below carry the false-positive defence instead.
_ASSIGNED_SECRET = re.compile(
    r"(?i)(secret|passwd|password|api[_-]?key|access[_-]?key|"
    r"private[_-]?key|client[_-]?secret|auth[_-]?token|bearer|"
    r"credential|token)\W{0,4}[:=]\s*[\"']?"
    r"([0-9A-Za-z+/_-]{24,}={0,2})")

_PLACEHOLDER = re.compile(
    r"(?i)redact|example|placeholder|your[_-]|xxxx|\*{4}|changeme|"
    r"dummy|sample|<[a-z_]+>|\bfake\b|test[_-]?key")


def _entropy(s):
    """Shannon entropy in bits/char. Prose and identifiers sit low."""
    if not s:
        return 0.0
    import math
    counts = {}
    for ch in s:
        counts[ch] = counts.get(ch, 0) + 1
    n = float(len(s))
    return -sum((c / n) * math.log2(c / n) for c in counts.values())


def scan_secrets(text):
    """Return the sorted CLASS names of credential shapes found in text.

    Empty list means nothing matched. The matched substrings are deliberately
    not returned: no caller can then leak them by accident.
    """
    if not text:
        return []
    found = set()
    for name, pat in _SECRET_PATTERNS:
        if pat.search(text):
            found.add(name)
    for m in _ASSIGNED_SECRET.finditer(text):
        blob = m.group(2)
        if _PLACEHOLDER.search(blob):
            continue
        if _entropy(blob) < 3.4:
            continue
        found.add("assigned-credential-blob")
        break
    return sorted(found)


def redact_secrets(text):
    """Same detector, but blank the values instead of refusing the message.

    Used on the human-driven surfaces — /sh output, the /log tail, the live
    progress ticker. Refusing there would break routine work, and a gate that
    breaks routine work gets deleted and then protects nothing.
    """
    if not text:
        return text
    for name, pat in _SECRET_PATTERNS:
        text = pat.sub(f"[redacted:{name}]", text)

    def _sub(m):
        blob = m.group(2)
        if _PLACEHOLDER.search(blob) or _entropy(blob) < 3.4:
            return m.group(0)
        return (m.group(0)[:m.start(2) - m.start(0)]
                + "[redacted:assigned-credential-blob]")
    return _ASSIGNED_SECRET.sub(_sub, text)


def force_ipv4():
    """This network black-holes some IPv6 routes; pin to IPv4."""
    real = socket.getaddrinfo

    def ipv4_only(host, port, family=0, *args, **kwargs):
        return real(host, port, socket.AF_INET, *args, **kwargs)

    socket.getaddrinfo = ipv4_only


def load_config():
    cfg = strict_json_loads(read_private(CONFIG_PATH), CONFIG_PATH)
    if not isinstance(cfg, dict):
        raise ValueError("config.json must contain one JSON object")
    cfg.setdefault("allowed_user_ids", [])
    cfg.setdefault("default_cwd", os.path.expanduser("~/dev"))
    cfg.setdefault("claude_bin", os.path.expanduser("~/.local/bin/claude"))
    cfg.setdefault("kimi_bin", os.path.expanduser("~/.kimi-code/bin/kimi"))
    cfg.setdefault("codex_bin",
                   "/Applications/ChatGPT.app/Contents/Resources/codex")
    cfg.setdefault("cursor_bin", os.path.expanduser("~/.local/bin/agent"))
    cfg.setdefault("grok_bin", os.path.expanduser("~/.local/bin/grok"))
    cfg.setdefault("claude_timeout_sec", 3600)
    cfg.setdefault("codex_timeout_sec", cfg["claude_timeout_sec"])
    cfg.setdefault("cursor_timeout_sec", cfg["claude_timeout_sec"])
    cfg.setdefault("grok_timeout_sec", cfg["claude_timeout_sec"])
    cfg.setdefault("codex_sandbox", "workspace-write")
    # Headless Cursor from Telegram is the same high-authority surface as
    # Claude bypassPermissions. --force avoids a hung approval prompt on
    # the phone. --approve-mcps stays off.
    cfg.setdefault("cursor_force", True)
    # A Telegram message is a higher-risk entry point than an interactive
    # desktop task. Do not load custom global config (including custom MCP
    # servers) unless the owner consciously opts in via config.json.
    cfg.setdefault("codex_ignore_user_config", True)
    cfg.setdefault("codex_ignore_rules", True)
    # Keep repository-owned settings and instructions, but do not inherit
    # user/local hooks and plugins into a full-permission remote session.
    cfg.setdefault("claude_setting_sources", "project")
    # Names only, matched against ~/.claude.json. Anything not listed here is
    # invisible to a bridge run. Measured 2026-08-03: an unrestricted run saw
    # 14 servers including safari, playwright, Gmail, Drive, Slack and Notion.
    cfg.setdefault("mcp_allow", list(MCP_ALLOW_DEFAULT))
    cfg.setdefault("force_ipv4", True)

    if not isinstance(cfg.get("bot_token"), str):
        raise ValueError("bot_token must be a string")
    allowed = cfg["allowed_user_ids"]
    if (not isinstance(allowed, list)
            or any(isinstance(value, bool) or not isinstance(value, int)
                   or value <= 0 for value in allowed)
            or len(set(allowed)) != len(allowed)):
        raise ValueError("allowed_user_ids must be unique positive integers")
    for name in ("default_cwd", "claude_bin", "kimi_bin", "codex_bin",
                 "cursor_bin", "grok_bin"):
        if not isinstance(cfg[name], str) or not cfg[name].strip():
            raise ValueError(f"{name} must be a nonempty path string")
        cfg[name] = os.path.realpath(os.path.expanduser(cfg[name]))
    for name, program in (("cursor_bin", "agent"), ("grok_bin", "grok")):
        if not os.path.isfile(cfg[name]):
            found = shutil.which(program)
            if found:
                cfg[name] = os.path.realpath(found)
    for name in ("claude_timeout_sec", "codex_timeout_sec",
                 "cursor_timeout_sec", "grok_timeout_sec"):
        value = cfg[name]
        if (isinstance(value, bool) or not isinstance(value, int)
                or not 30 <= value <= 86400):
            raise ValueError(f"{name} must be an integer from 30 to 86400")
    for name in ("codex_ignore_user_config", "codex_ignore_rules",
                 "force_ipv4", "cursor_force"):
        if not isinstance(cfg[name], bool):
            raise ValueError(f"{name} must be true or false")
    if cfg["codex_sandbox"] not in ("read-only", "workspace-write"):
        raise ValueError("codex_sandbox must be read-only or workspace-write")
    allow = cfg["mcp_allow"]
    if (not isinstance(allow, list)
            or any(not isinstance(name, str) or not name
                   or len(name) > 128 or any(ord(ch) < 32 for ch in name)
                   for name in allow)
            or len(set(allow)) != len(allow)):
        raise ValueError("mcp_allow must contain unique safe server names")
    sources = cfg["claude_setting_sources"]
    if not isinstance(sources, str):
        raise ValueError("claude_setting_sources must be a comma-separated string")
    source_parts = [part.strip() for part in sources.split(",") if part.strip()]
    if (not source_parts or len(set(source_parts)) != len(source_parts)
            or not set(source_parts) <= {"user", "project", "local"}):
        raise ValueError("claude_setting_sources may use user, project, local")
    cfg["claude_setting_sources"] = ",".join(source_parts)
    return cfg


def fmt_elapsed(sec):
    sec = int(sec)
    if sec < 60:
        return f"{sec}s"
    return f"{sec // 60}m{sec % 60:02d}s"


def git_info(cwd):
    """'main (3 dirty)' or None if not a git repo."""
    try:
        b = subprocess.run(["git", "-C", cwd, "rev-parse",
                            "--abbrev-ref", "HEAD"],
                           capture_output=True, text=True, timeout=5)
        if b.returncode != 0:
            return None
        s = subprocess.run(["git", "-C", cwd, "status", "--porcelain"],
                           capture_output=True, text=True, timeout=5)
        dirty = sum(1 for ln in s.stdout.splitlines() if ln.strip())
        branch = b.stdout.strip()
        return f"{branch} ({dirty} dirty)" if dirty else f"{branch} (clean)"
    except Exception:
        return None


def md_to_html(text):
    """Best-effort Claude-markdown -> Telegram HTML (b/code/pre/a only)."""
    segs = re.split(r"```[\w+-]*\n?(.*?)```", text, flags=re.S)
    out = []
    for i, seg in enumerate(segs):
        if i % 2:  # fenced code block
            out.append(f"<pre>{html.escape(seg.rstrip())}</pre>")
            continue
        s = html.escape(seg)
        s = re.sub(r"`([^`\n]+)`", r"<code>\1</code>", s)
        s = re.sub(r"\*\*(.+?)\*\*", r"<b>\1</b>", s)
        s = re.sub(r"^#{1,6}\s+(.+)$", r"<b>\1</b>", s, flags=re.M)
        s = re.sub(r"\[([^\]\n]+)\]\((https?://[^)\s]+)\)",
                   r'<a href="\2">\1</a>', s)
        out.append(s)
    return "".join(out)


def kb(rows):
    """rows = [[('label','data'),...],...] -> reply_markup JSON."""
    return json.dumps({"inline_keyboard": [
        [{"text": t, "callback_data": d} for t, d in row] for row in rows]})


STOP_KB = kb([[("🛑 stop", "stop")]])


# ---------------------------------------------------------------- telegram

class TelegramError(Exception):
    pass


class Telegram:
    def __init__(self, token):
        self.token = token
        self.api = f"https://api.telegram.org/bot{token}"

    def call(self, method, params=None, timeout=60, retries=2):
        data = urllib.parse.urlencode(params or {}).encode()
        for attempt in range(retries + 1):
            req = urllib.request.Request(f"{self.api}/{method}", data=data)
            try:
                with urllib.request.urlopen(req, timeout=timeout) as resp:
                    payload = strict_json_loads(
                        read_bounded(resp, MAX_API_RESPONSE,
                                     f"Telegram {method} response"),
                        f"Telegram {method} response")
                if not isinstance(payload, dict) or payload.get("ok") is not True:
                    description = (payload.get("description")
                                   if isinstance(payload, dict) else None)
                    raise TelegramError(description or
                                        f"{method}: malformed API response")
                return payload
            except urllib.error.HTTPError as e:
                try:
                    body = strict_json_loads(
                        read_bounded(e, MAX_ERROR_RESPONSE,
                                     f"Telegram {method} error"),
                        f"Telegram {method} error")
                except (TypeError, UnicodeError, ValueError):
                    body = {}
                if not isinstance(body, dict):
                    body = {}
                desc = body.get("description", f"HTTP {e.code}")
                if e.code == 429 and attempt < retries:
                    parameters = body.get("parameters")
                    if not isinstance(parameters, dict):
                        parameters = {}
                    wait = parameters.get("retry_after", 3)
                    if isinstance(wait, bool) or not isinstance(wait, int):
                        wait = 3
                    wait = min(max(wait, 1), 300)
                    log(f"telegram 429 on {method}; retrying in {wait}s")
                    time.sleep(wait + 0.5)
                    continue
                raise TelegramError(f"HTTP {e.code}: {desc}") from None
        raise TelegramError(f"{method}: retries exhausted")

    def get_updates(self, offset):
        try:
            r = self.call("getUpdates",
                          {"offset": offset, "timeout": 50,
                           "allowed_updates":
                               '["message","callback_query"]'},
                          timeout=70)
            self._fails = 0
            return r.get("result", [])
        except Exception as e:
            # A 401 (revoked token) and a 409 (another poller holds this bot)
            # are both permanent: the old code folded them into a blanket
            # except and spun every 5s forever, alive and answering nothing.
            # Name them, and let launchd restart us rather than wedge.
            text = str(e)
            self._fails = getattr(self, "_fails", 0) + 1
            if "401" in text or "Unauthorized" in text:
                log("FATAL: Telegram rejected the token (401) — revoked? exiting")
                os._exit(1)
            if "409" in text or "Conflict" in text:
                log("FATAL: 409 Conflict: another poller holds this bot token; "
                    "exiting so only one survives")
                os._exit(1)
            backoff = min(5 * 2 ** (self._fails - 1), 300)
            log(f"getUpdates error ({self._fails}, retry in {backoff}s): {e}")
            time.sleep(backoff)
            return []

    def webhook_info(self):
        return self.call("getWebhookInfo", timeout=15)

    def set_my_commands(self, commands):
        return self.call("setMyCommands",
                         {"commands": json.dumps(commands, allow_nan=False)},
                         timeout=15)

    def send(self, chat_id, text, reply_markup=None, message_thread_id=None):
        """Plain-text send (chunked). Returns message_id of first chunk."""
        if not text.strip():
            text = "(empty response)"
        first_id = None
        chunks = [text[i:i + MAX_MSG] for i in range(0, len(text), MAX_MSG)]
        for chunk in chunks:
            params = {"chat_id": chat_id, "text": chunk}
            if message_thread_id is not None:
                params["message_thread_id"] = message_thread_id
            if reply_markup and first_id is None:
                params["reply_markup"] = reply_markup
            try:
                r = self.call("sendMessage", params)
            except Exception as e:
                log(f"sendMessage error: {e}")
                r = None
            if first_id is None and r and r.get("result"):
                first_id = r["result"].get("message_id")
        return first_id

    def send_html(self, chat_id, html_text, fallback_plain,
                  message_thread_id=None):
        """Single-message HTML send; falls back to plain chunks."""
        try:
            self.call("sendMessage",
                      {"chat_id": chat_id, "text": html_text,
                       "parse_mode": "HTML",
                       "disable_web_page_preview": "true",
                       **({"message_thread_id": message_thread_id}
                          if message_thread_id is not None else {})})
        except Exception as e:
            log(f"HTML send failed ({e}); falling back to plain")
            self.send(chat_id, fallback_plain,
                      message_thread_id=message_thread_id)

    def edit(self, chat_id, message_id, text, reply_markup=None):
        params = {"chat_id": chat_id, "message_id": message_id,
                  "text": text[:MAX_MSG]}
        if reply_markup:
            params["reply_markup"] = reply_markup
        try:
            self.call("editMessageText", params, timeout=15, retries=0)
        except Exception as e:
            if "not modified" not in str(e):
                log(f"editMessageText error: {e}")

    def answer_callback(self, cq_id, text=""):
        try:
            self.call("answerCallbackQuery",
                      {"callback_query_id": cq_id, "text": text[:180]},
                      timeout=10, retries=0)
        except Exception:
            pass

    def typing(self, chat_id, message_thread_id=None):
        try:
            params = {"chat_id": chat_id, "action": "typing"}
            if message_thread_id is not None:
                params["message_thread_id"] = message_thread_id
            self.call("sendChatAction", params,
                      timeout=10, retries=0)
        except Exception:
            pass

    def download(self, file_id, dest_dir, name_hint=None):
        """Fetch a Telegram file to dest_dir; returns local path."""
        r = self.call("getFile", {"file_id": file_id}, timeout=30)
        result = r.get("result")
        if not isinstance(result, dict):
            raise TelegramError("getFile returned no file object")
        remote = result.get("file_path")
        size = result.get("file_size")
        if not isinstance(remote, str) or not remote or "\x00" in remote:
            raise TelegramError("getFile returned an invalid file path")
        if (size is not None
                and (isinstance(size, bool) or not isinstance(size, int)
                     or size < 0 or size > MAX_DOWNLOAD)):
            raise TelegramError("Telegram file exceeds the 20 MiB download limit")
        ensure_private_dir(dest_dir)
        suggested = os.path.basename(name_hint or remote)
        safe_name = re.sub(r"[^0-9A-Za-z._-]+", "_", suggested)[:120]
        safe_name = safe_name.strip(".") or f"file-{str(file_id)[:8]}"
        fd, dest = tempfile.mkstemp(
            prefix=f"{time.strftime('%H%M%S')}-", suffix="-" + safe_name,
            dir=dest_dir)
        try:
            os.fchmod(fd, PRIVATE_FILE_MODE)
            remote_url = urllib.parse.quote(remote, safe="/")
            url = f"https://api.telegram.org/file/bot{self.token}/{remote_url}"
            with urllib.request.urlopen(url, timeout=300) as resp:
                declared = resp.headers.get("Content-Length")
                if (declared is not None
                        and (not declared.isdigit()
                             or int(declared) > MAX_DOWNLOAD)):
                    raise TelegramError("Telegram download exceeds 20 MiB")
                total = 0
                while True:
                    block = resp.read(min(65536, MAX_DOWNLOAD - total + 1))
                    if not block:
                        break
                    total += len(block)
                    if total > MAX_DOWNLOAD:
                        raise TelegramError("Telegram download exceeds 20 MiB")
                    os.write(fd, block)
            os.fsync(fd)
            return dest
        except Exception:
            try:
                os.unlink(dest)
            except FileNotFoundError:
                pass
            raise
        finally:
            os.close(fd)

    def send_document(self, chat_id, path, caption="", message_thread_id=None):
        boundary = uuid.uuid4().hex
        resolved = os.path.realpath(path)
        flags = os.O_RDONLY | getattr(os, "O_CLOEXEC", 0)
        flags |= getattr(os, "O_NOFOLLOW", 0)
        fd = os.open(resolved, flags)
        try:
            info = os.fstat(fd)
            if not stat.S_ISREG(info.st_mode):
                raise TelegramError("document is not a regular file")
            if info.st_size > MAX_UPLOAD:
                raise TelegramError("document exceeds Telegram's 50 MiB limit")
            with os.fdopen(fd, "rb", closefd=False) as handle:
                file_data = handle.read(MAX_UPLOAD + 1)
            if len(file_data) > MAX_UPLOAD:
                raise TelegramError("document exceeds Telegram's 50 MiB limit")
        finally:
            os.close(fd)
        parts = []
        fields = [("chat_id", str(chat_id)), ("caption", caption[:1000])]
        if message_thread_id is not None:
            fields.append(("message_thread_id", str(message_thread_id)))
        for name, value in fields:
            value = value.replace("\r", " ").replace("\n", " ")
            parts.append(
                f"--{boundary}\r\nContent-Disposition: form-data; "
                f"name=\"{name}\"\r\n\r\n{value}\r\n".encode())
        filename = re.sub(r"[^0-9A-Za-z._-]+", "_",
                          os.path.basename(resolved))[:160] or "document.bin"
        parts.append(
            f"--{boundary}\r\nContent-Disposition: form-data; "
            f"name=\"document\"; filename=\"{filename}\"\r\n"
            f"Content-Type: application/octet-stream\r\n\r\n".encode())
        parts.append(file_data)
        parts.append(f"\r\n--{boundary}--\r\n".encode())
        body = b"".join(parts)
        req = urllib.request.Request(
            f"{self.api}/sendDocument", data=body,
            headers={"Content-Type":
                     f"multipart/form-data; boundary={boundary}"})
        with urllib.request.urlopen(req, timeout=300) as resp:
            payload = strict_json_loads(
                read_bounded(resp, MAX_API_RESPONSE,
                             "Telegram sendDocument response"),
                "Telegram sendDocument response")
        if not isinstance(payload, dict) or payload.get("ok") is not True:
            raise TelegramError("sendDocument returned a malformed response")
        return payload


# ---------------------------------------------------------------- claude

TOOL_ICONS = {
    "Bash": "🔧", "Edit": "✏️", "Write": "📝", "Read": "📖",
    "Glob": "🔍", "Grep": "🔍", "WebFetch": "🌐", "WebSearch": "🌐",
    "Task": "🤖", "Agent": "🤖", "TodoWrite": "📋",
}


def describe_tool(name, tool_input):
    """One short human line per tool call, for the live progress view."""
    icon = TOOL_ICONS.get(name, "⚙️")
    detail = ""
    if name == "Bash":
        detail = (tool_input.get("description")
                  or tool_input.get("command", ""))
    elif name in ("Edit", "Write", "Read", "NotebookEdit"):
        detail = os.path.basename(tool_input.get("file_path", ""))
    elif name in ("Glob", "Grep"):
        detail = tool_input.get("pattern", "")
    elif name == "WebFetch":
        detail = tool_input.get("url", "")
    elif name == "WebSearch":
        detail = tool_input.get("query", "")
    elif name in ("Task", "Agent"):
        detail = tool_input.get("description", "")
    detail = " ".join(str(detail).split())
    if len(detail) > 60:
        detail = detail[:57] + "…"
    return f"{icon} {name}: {detail}" if detail else f"{icon} {name}"


class EngineRun:
    """One cancellable headless engine invocation (base class).

    The child is started in its own process group so cancel() kills the
    whole tree (engine + whatever shell children it spawned), escalating
    SIGTERM -> SIGKILL after KILL_GRACE seconds.
    """

    engine_name = "claude"

    def __init__(self, cfg, chat, prompt):
        self.cfg = cfg
        self.chat = chat
        self.prompt = prompt
        self.proc = None
        self.stop_reason = None      # None | "user" | "timeout"

    def cancel(self, reason="user"):
        if self.stop_reason is None:
            self.stop_reason = reason
        p = self.proc
        if not p or p.poll() is not None:
            return
        try:
            os.killpg(p.pid, signal.SIGTERM)
        except (OSError, ProcessLookupError):
            return

        def hard_kill():
            if p.poll() is None:
                try:
                    os.killpg(p.pid, signal.SIGKILL)
                except (OSError, ProcessLookupError):
                    pass
        t = threading.Timer(KILL_GRACE, hard_kill)
        t.daemon = True
        t.start()

    def _stopped_text(self):
        return ("⏱ timed out after "
                + fmt_elapsed(self.cfg["claude_timeout_sec"])
                if self.stop_reason == "timeout" else "🛑 stopped.")


class ClaudeRun(EngineRun):
    """Streaming headless Claude Code run."""

    engine_name = "claude"

    def execute(self, on_event):
        """Run claude; on_event(desc) per action. Returns result dict:
        {sid, text, ok, cost, turns}. Retries once in-place on a stale
        --resume id, so a /stop during the retry still lands on self."""
        for _ in range(2):
            outcome = self._run_once(on_event)
            if outcome is not None:
                return outcome
            # stale --resume id: session cleared by _run_once; go again
            if self.stop_reason:
                return {"sid": None, "ok": False, "text": "🛑 stopped."}
        err = self._stderr or "no output"
        return {"sid": None, "ok": False,
                "text": f"⚠️ claude gave no result: {err[:1500]}"}

    def _run_once(self, on_event):
        cmd = [
            self.cfg["claude_bin"], "-p",
            "--output-format", "stream-json", "--verbose",
            "--permission-mode", "bypassPermissions",
            "--dangerously-skip-permissions",
            "--setting-sources", self.cfg.get(
                "claude_setting_sources", "project"),
            "--no-chrome",
        ]
        # Deny-by-default MCP. --strict-mcp-config is what actually drops the
        # user-scope servers; --mcp-config alone would MERGE with them and
        # leave safari and MCP_DOCKER right where they were.
        mcp_path = write_mcp_config(self.cfg.get("mcp_allow",
                                                 MCP_ALLOW_DEFAULT))
        cmd += ["--mcp-config", mcp_path or EMPTY_MCP, "--strict-mcp-config"]
        model = self.chat.get("model")
        if model and model != "default":
            cmd += ["--model", MODEL_IDS.get(model, model)]
        sid = self.chat.get("session_id")
        if sid == CONTINUE:
            cmd += ["--continue"]
        elif sid:
            cmd += ["--resume", sid]

        try:
            self.proc = subprocess.Popen(
                cmd, cwd=self.chat.get("cwd") or self.cfg["default_cwd"],
                stdin=subprocess.PIPE, stdout=subprocess.PIPE,
                stderr=subprocess.PIPE, text=True,
                start_new_session=True)
        except FileNotFoundError:
            return {"sid": None, "ok": False,
                    "text": f"claude binary not found at "
                            f"{self.cfg['claude_bin']}"}

        self._stderr = ""
        proc = self.proc
        process_input = getattr(proc, "stdin", None)
        if process_input is not None:
            process_input.write(self.prompt)
            process_input.close()

        def read_err():
            try:
                self._stderr = proc.stderr.read().strip()
            except Exception:
                pass
        threading.Thread(target=read_err, daemon=True).start()

        killer = threading.Timer(self.cfg["claude_timeout_sec"],
                                 lambda: self.cancel("timeout"))
        killer.daemon = True
        killer.start()

        new_sid, result = None, None
        try:
            for line in proc.stdout:
                line = line.strip()
                if not line:
                    continue
                try:
                    e = json.loads(line)
                except ValueError:
                    continue
                t = e.get("type")
                if t == "system" and e.get("subtype") == "init":
                    new_sid = e.get("session_id")
                elif t == "assistant":
                    for b in (e.get("message") or {}).get("content", []):
                        if b.get("type") == "tool_use":
                            on_event(describe_tool(b.get("name", "?"),
                                                   b.get("input") or {}))
                        elif (b.get("type") == "text"
                              and b.get("text", "").strip()):
                            snip = " ".join(b["text"].split())
                            on_event("💬 " + (snip[:57] + "…"
                                              if len(snip) > 60 else snip))
                elif t == "result":
                    result = e
        finally:
            killer.cancel()
            proc.wait()

        if self.stop_reason and (result is None or result.get("is_error")):
            return {"sid": (result or {}).get("session_id") or new_sid,
                    "ok": False, "text": self._stopped_text()}
        if result is not None:
            text = result.get("result") or "(no result text)"
            if result.get("is_error"):
                text = "⚠️ Claude reported an error:\n" + text
            return {"sid": result.get("session_id") or new_sid,
                    "ok": not result.get("is_error"), "text": text,
                    "cost": result.get("total_cost_usd"),
                    "turns": result.get("num_turns")}
        if sid:
            # no result event with a --resume id: assume stale, signal retry
            self.chat["session_id"] = None
            return None
        return {"sid": new_sid, "ok": False,
                "text": f"⚠️ claude exited {proc.returncode}: "
                        f"{(self._stderr or 'no output')[:1500]}"}


class KimiRun(EngineRun):
    """Headless Kimi Code run (text mode; prompt mode auto-approves).

    Session continuity uses kimi's -c (continue previous session for the
    working directory), armed after the first successful run per chat.
    """

    engine_name = "kimi"

    def execute(self, on_event):
        cmd = [self.cfg["kimi_bin"], f"--prompt={self.prompt}",
               "--output-format", "text"]
        if self.chat.get("kimi_continue"):
            cmd += ["-c"]
        try:
            self.proc = subprocess.Popen(
                cmd, cwd=self.chat.get("cwd") or self.cfg["default_cwd"],
                stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True,
                start_new_session=True)
        except FileNotFoundError:
            return {"sid": None, "ok": False,
                    "text": f"kimi binary not found at "
                            f"{self.cfg['kimi_bin']} — is Kimi Code "
                            f"installed?"}

        proc = self.proc
        err_buf = []
        threading.Thread(
            target=lambda: err_buf.append(proc.stderr.read()),
            daemon=True).start()
        killer = threading.Timer(self.cfg["claude_timeout_sec"],
                                 lambda: self.cancel("timeout"))
        killer.daemon = True
        killer.start()

        out_lines = []
        try:
            for line in proc.stdout:
                out_lines.append(line)
                snip = " ".join(line.split())
                if snip:
                    on_event("🌙 " + (snip[:57] + "…"
                                      if len(snip) > 60 else snip))
        finally:
            killer.cancel()
            proc.wait()

        if self.stop_reason:
            return {"sid": None, "ok": False, "text": self._stopped_text()}
        out = "".join(out_lines).strip()
        err = ("".join(err_buf)).strip()
        if proc.returncode != 0:
            detail = err or out or "no output"
            hint = ""
            if "402" in detail or "membership" in detail.lower():
                hint = ("\n\n(Kimi membership looks inactive — renew it "
                        "or run `kimi login` on the Mac.)")
            return {"sid": None, "ok": False,
                    "text": f"⚠️ kimi exited {proc.returncode}: "
                            f"{detail[:1200]}{hint}"}
        self.chat["kimi_continue"] = True
        return {"sid": None, "ok": True, "text": out or "(empty response)"}


def describe_codex_item(item):
    """One compact progress line for a Codex JSONL item."""
    kind = item.get("type") or "item"
    if kind == "command_execution":
        command = " ".join(str(item.get("command") or "").split())
        return "🔧 command: " + (command[:57] + "…"
                                if len(command) > 60 else command)
    if kind == "mcp_tool_call":
        server = item.get("server") or item.get("server_name") or "mcp"
        tool = item.get("tool") or item.get("tool_name") or "tool"
        return f"⚙️ {server}: {tool}"
    if kind == "web_search":
        query = " ".join(str(item.get("query") or "").split())
        return "🌐 search: " + (query[:58] + "…"
                               if len(query) > 61 else query)
    if kind in ("file_change", "file_changes"):
        return "✏️ file changes"
    if kind not in ("agent_message", "reasoning"):
        return "⚙️ " + kind.replace("_", " ")
    return None


class CodexRun(EngineRun):
    """Streaming, resumable OpenAI Codex non-interactive run."""

    engine_name = "codex"

    def execute(self, on_event):
        for _ in range(2):
            result = self._run_once(on_event)
            if not result.pop("stale", False):
                return result
            self.chat["codex_session_id"] = None
        return {"sid": None, "ok": False,
                "text": "⚠️ Codex could not resume that session. Use /new."}

    def _sandbox(self):
        sandbox = self.cfg.get("codex_sandbox", "workspace-write")
        return (sandbox if sandbox in ("read-only", "workspace-write")
                else "workspace-write")

    def _stopped_text(self):
        return ("⏱ timed out after "
                + fmt_elapsed(self.cfg.get("codex_timeout_sec", 3600))
                if self.stop_reason == "timeout" else "🛑 stopped.")

    def _command(self, cwd):
        sid = self.chat.get("codex_session_id")
        if sid:
            # `exec resume` has no --sandbox flag, so reassert the equivalent
            # config value. Resume reloads configuration and must not silently
            # widen a Telegram session after its first turn.
            cmd = [self.cfg["codex_bin"], "exec", "resume", "--json",
                   "-c", f'sandbox_mode="{self._sandbox()}"']
            if self.cfg.get("codex_ignore_user_config", True):
                cmd.append("--ignore-user-config")
            if self.cfg.get("codex_ignore_rules", True):
                cmd.append("--ignore-rules")
            # "--" so a chat message can never be read as a flag. Without it a
            # prompt beginning with "--sandbox" or
            # "--dangerously-bypass-approvals-and-sandbox" is parsed as an
            # option and silently widens the run we just constrained.
            return cmd + ["--", sid, "-"]

        cmd = [self.cfg["codex_bin"], "exec", "--json", "--color", "never",
               "--sandbox", self._sandbox(), "--cd", cwd]
        if self.cfg.get("codex_ignore_user_config", True):
            cmd.append("--ignore-user-config")
        if self.cfg.get("codex_ignore_rules", True):
            cmd.append("--ignore-rules")
        cmd.extend(["--", "-"])
        return cmd

    def _run_once(self, on_event):
        cwd = self.chat.get("cwd") or self.cfg["default_cwd"]
        if git_info(cwd) is None:
            return {"sid": None, "ok": False,
                    "text": ("⚠️ Codex needs a Git repository. Use /repos or "
                             "/repo <name> first.")}

        cmd = self._command(cwd)
        try:
            self.proc = subprocess.Popen(
                cmd, cwd=cwd, stdin=subprocess.PIPE,
                stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                text=True, start_new_session=True)
        except FileNotFoundError:
            return {"sid": None, "ok": False,
                    "text": f"Codex binary not found at {self.cfg['codex_bin']}"}

        proc = self.proc
        process_input = getattr(proc, "stdin", None)
        if process_input is not None:
            process_input.write(self.prompt)
            process_input.close()
        stderr = []

        def read_err():
            try:
                stderr.append(proc.stderr.read())
            except Exception:
                pass
        threading.Thread(target=read_err, daemon=True).start()

        killer = threading.Timer(self.cfg.get("codex_timeout_sec", 3600),
                                 lambda: self.cancel("timeout"))
        killer.daemon = True
        killer.start()

        new_sid = None
        final_text = None
        event_errors = []
        try:
            for line in proc.stdout:
                line = line.strip()
                if not line:
                    continue
                try:
                    event = json.loads(line)
                except ValueError:
                    continue
                event_type = event.get("type")
                if event_type == "thread.started":
                    new_sid = event.get("thread_id") or new_sid
                elif event_type in ("item.started", "item.completed"):
                    item = event.get("item") or {}
                    if (event_type == "item.completed"
                            and item.get("type") == "agent_message"
                            and str(item.get("text") or "").strip()):
                        final_text = item["text"]
                    elif (event_type == "item.completed"
                          and item.get("type") == "error"
                          and item.get("message")):
                        event_errors.append(str(item["message"]))
                    elif event_type == "item.started":
                        desc = describe_codex_item(item)
                        if desc:
                            on_event(desc)
                elif event_type in ("error", "turn.failed"):
                    detail = event.get("message") or event.get("error")
                    if isinstance(detail, dict):
                        detail = detail.get("message") or str(detail)
                    if detail:
                        event_errors.append(str(detail))
        finally:
            killer.cancel()
            proc.wait()

        err = "\n".join(stderr).strip()
        if self.stop_reason:
            return {"sid": new_sid or self.chat.get("codex_session_id"),
                    "ok": False, "text": self._stopped_text()}
        if proc.returncode == 0 and final_text:
            return {"sid": new_sid or self.chat.get("codex_session_id"),
                    "ok": True, "text": final_text}

        detail = "\n".join(event_errors) or err or "no result"
        lower = detail.lower()
        stale = bool(self.chat.get("codex_session_id")
                     and "session" in lower
                     and ("not found" in lower or "resume" in lower))
        return {"sid": new_sid, "ok": False, "stale": stale,
                "text": f"⚠️ Codex exited {proc.returncode}: {detail[:1500]}"}


def describe_cursor_tool(event):
    """One compact progress line for a Cursor stream-json tool_call."""
    call = event.get("tool_call") or {}
    if not isinstance(call, dict) or not call:
        name = event.get("name") or "tool"
        return f"⚙️ {name}"
    kind, body = next(iter(call.items()))
    label = kind.replace("ToolCall", "").replace("toolCall", "") or "tool"
    args = (body or {}).get("args") if isinstance(body, dict) else {}
    detail = ""
    if isinstance(args, dict):
        detail = (args.get("path") or args.get("file_path")
                  or args.get("command") or args.get("query") or "")
    detail = " ".join(str(detail).split())
    if len(detail) > 60:
        detail = detail[:57] + "…"
    return f"⚙️ {label}: {detail}" if detail else f"⚙️ {label}"


class CursorRun(EngineRun):
    """Headless Cursor agent (`agent -p`, stream-json, workspace-scoped)."""

    engine_name = "cursor"

    def execute(self, on_event):
        for _ in range(2):
            outcome = self._run_once(on_event)
            if outcome is not None:
                return outcome
            if self.stop_reason:
                return {"sid": None, "ok": False, "text": "🛑 stopped."}
        err = self._stderr or "no output"
        return {"sid": None, "ok": False,
                "text": f"⚠️ cursor gave no result: {err[:1500]}"}

    def _command(self, cwd):
        cmd = [
            self.cfg["cursor_bin"], "-p",
            "--output-format", "stream-json",
            "--trust",
            "--workspace", cwd,
        ]
        if self.cfg.get("cursor_force", True):
            cmd.append("--force")
        sid = self.chat.get("cursor_session_id")
        if sid == CONTINUE:
            cmd.append("--continue")
        elif sid:
            cmd.extend(["--resume", sid])
        # "--" so a leading-dash prompt cannot become an extra flag.
        cmd.extend(["--", self.prompt])
        return cmd

    def _run_once(self, on_event):
        cwd = self.chat.get("cwd") or self.cfg["default_cwd"]
        cmd = self._command(cwd)
        try:
            self.proc = subprocess.Popen(
                cmd, cwd=cwd, stdout=subprocess.PIPE,
                stderr=subprocess.PIPE, text=True, start_new_session=True)
        except FileNotFoundError:
            return {"sid": None, "ok": False,
                    "text": f"Cursor agent not found at {self.cfg['cursor_bin']}"}

        proc = self.proc
        self._stderr = ""

        def read_err():
            try:
                self._stderr = proc.stderr.read().strip()
            except Exception:
                pass
        threading.Thread(target=read_err, daemon=True).start()

        killer = threading.Timer(
            self.cfg.get("cursor_timeout_sec",
                         self.cfg.get("claude_timeout_sec", 3600)),
            lambda: self.cancel("timeout"))
        killer.daemon = True
        killer.start()

        new_sid, result = None, None
        try:
            for line in proc.stdout:
                line = line.strip()
                if not line:
                    continue
                try:
                    event = json.loads(line)
                except ValueError:
                    continue
                kind = event.get("type")
                if kind == "system" and event.get("subtype") == "init":
                    new_sid = event.get("session_id") or new_sid
                elif kind == "tool_call" and event.get("subtype") == "started":
                    on_event(describe_cursor_tool(event))
                elif kind == "assistant":
                    for block in (event.get("message") or {}).get("content", []):
                        if block.get("type") == "text" and block.get("text", "").strip():
                            snip = " ".join(block["text"].split())
                            on_event("💬 " + (snip[:57] + "…"
                                              if len(snip) > 60 else snip))
                elif kind == "result":
                    result = event
                    new_sid = event.get("session_id") or new_sid
        finally:
            killer.cancel()
            proc.wait()

        if self.stop_reason and (result is None or result.get("is_error")):
            return {"sid": (result or {}).get("session_id") or new_sid,
                    "ok": False, "text": self._stopped_text()}
        if result is not None:
            text = result.get("result") or "(no result text)"
            if result.get("is_error"):
                text = "⚠️ Cursor reported an error:\n" + text
            return {"sid": result.get("session_id") or new_sid,
                    "ok": not result.get("is_error"), "text": text}
        if self.chat.get("cursor_session_id"):
            self.chat["cursor_session_id"] = None
            return None
        return {"sid": new_sid, "ok": False,
                "text": f"⚠️ cursor exited {proc.returncode}: "
                        f"{(self._stderr or 'no output')[:1500]}"}


class GrokRun(EngineRun):
    """Headless Grok CLI (`grok --single`, one-shot)."""

    engine_name = "grok"

    def _command(self, cwd):
        cmd = [self.cfg["grok_bin"], "--single", self.prompt,
               "--cwd", cwd, "--output-format", "plain"]
        model = self.chat.get("model")
        if model and model not in ("default", "off"):
            cmd.extend(["-m", model])
        return cmd

    def execute(self, on_event):
        cwd = self.chat.get("cwd") or self.cfg["default_cwd"]
        cmd = self._command(cwd)
        try:
            self.proc = subprocess.Popen(
                cmd, cwd=cwd, stdout=subprocess.PIPE,
                stderr=subprocess.PIPE, text=True, start_new_session=True)
        except FileNotFoundError:
            return {"sid": None, "ok": False,
                    "text": f"Grok CLI not found at {self.cfg['grok_bin']}"}

        proc = self.proc
        err_buf = []
        threading.Thread(
            target=lambda: err_buf.append(proc.stderr.read()),
            daemon=True).start()
        killer = threading.Timer(
            self.cfg.get("grok_timeout_sec",
                         self.cfg.get("claude_timeout_sec", 3600)),
            lambda: self.cancel("timeout"))
        killer.daemon = True
        killer.start()

        out_lines = []
        try:
            for line in proc.stdout:
                out_lines.append(line)
                snip = " ".join(line.split())
                if snip:
                    on_event("⚡ " + (snip[:57] + "…"
                                      if len(snip) > 60 else snip))
        finally:
            killer.cancel()
            proc.wait()

        if self.stop_reason:
            return {"sid": None, "ok": False, "text": self._stopped_text()}
        out = "".join(out_lines).strip()
        err = ("".join(err_buf)).strip()
        if proc.returncode != 0:
            detail = err or out or "no output"
            return {"sid": None, "ok": False,
                    "text": f"⚠️ grok exited {proc.returncode}: "
                            f"{detail[:1200]}"}
        return {"sid": None, "ok": True, "text": out or "(empty response)"}


ENGINES = {
    "claude": ClaudeRun,
    "codex": CodexRun,
    "kimi": KimiRun,
    "cursor": CursorRun,
    "grok": GrokRun,
}

BOT_COMMANDS = [
    {"command": "help", "description": "What this hub can do"},
    {"command": "status", "description": "Engine, repo, queue, uptime"},
    {"command": "engine", "description": "Pick claude, codex, kimi, cursor, grok"},
    {"command": "repos", "description": "Switch a ~/dev repository"},
    {"command": "new", "description": "Start a fresh engine session"},
    {"command": "attach", "description": "Continue the latest terminal session"},
    {"command": "stop", "description": "Kill the current run and drain the queue"},
    {"command": "clients", "description": "Telegram, Nicegram, and ll-hub"},
    {"command": "cost", "description": "Recent Claude spend"},
]


def webhook_is_clear(info):
    """A leftover webhook steals getUpdates and the Mac goes silent."""
    if not isinstance(info, dict):
        return False
    result = info.get("result") if "result" in info else info
    if not isinstance(result, dict):
        return False
    url = result.get("url") or ""
    return url == ""


def message_thread_id(message):
    value = (message or {}).get("message_thread_id")
    if isinstance(value, bool) or not isinstance(value, int) or value <= 0:
        return None
    return value


def conversation_key(chat_id, thread_id=None):
    return str(chat_id) if thread_id is None else f"{chat_id}:{thread_id}"


def advance_context(chat):
    """Invalidate queued/running jobs after an intentional context change."""
    chat["context_generation"] = chat.get("context_generation", 0) + 1


def snapshot_job(chat, prompt):
    """Freeze routing while leaving per-context session chaining to Worker."""
    return {
        "prompt": prompt,
        "engine": chat.get("engine", "claude"),
        "cwd": chat["cwd"],
        "model": chat.get("model"),
        "generation": chat.get("context_generation", 0),
        "session_id": chat.get("session_id"),
        "codex_session_id": chat.get("codex_session_id"),
        "cursor_session_id": chat.get("cursor_session_id"),
        "kimi_continue": chat.get("kimi_continue", False),
    }


def context_matches(chat, job):
    return (chat.get("context_generation", 0) == job["generation"]
            and chat.get("engine", "claude") == job["engine"]
            and chat.get("cwd") == job["cwd"]
            and chat.get("model") == job["model"])


def commit_context_if_current(live_chat, job, context):
    if not context_matches(live_chat, job):
        return False
    live_chat["session_id"] = context["session_id"]
    live_chat["codex_session_id"] = context["codex_session_id"]
    live_chat["cursor_session_id"] = context.get("cursor_session_id")
    if context["kimi_continue"]:
        live_chat["kimi_continue"] = True
    else:
        live_chat.pop("kimi_continue", None)
    return True


def update_context_from_run(context, chat, engine, result):
    """Carry session changes from a private run chat back to its queue context.

    A stale-session retry clears the relevant field on ``chat``.  Preserve
    that explicit ``None`` when the fresh retry also fails, otherwise the old
    stale ID would be committed to the live chat again.
    """
    field = ("codex_session_id" if engine == "codex"
             else "cursor_session_id" if engine == "cursor"
             else "session_id" if engine == "claude" else None)
    if field:
        if result.get("sid") is not None:
            chat[field] = result["sid"]
        context[field] = chat.get(field)
    context["kimi_continue"] = chat.get("kimi_continue", False)


# ---------------------------------------------------------------- worker

class Worker(threading.Thread):
    """Per-chat job runner: main loop stays free to answer commands."""

    def __init__(self, bridge, chat_id, thread_id=None):
        super().__init__(daemon=True)
        self.bridge = bridge
        self.chat_id = chat_id
        self.thread_id = thread_id
        self.jobs = queue.Queue()
        self.current = None          # ClaudeRun while busy
        self.current_started = None
        self.current_prompt = ""
        # Sessions for immutable queued contexts. This lets queued prompts keep
        # chaining even if the live chat switches engine/repository meanwhile.
        self.contexts = {}

    def submit(self, prompt):
        with self.bridge.state_lock:
            chat = self.bridge.chat_state(self.chat_id, self.thread_id)
            job = snapshot_job(chat, prompt)
        self.jobs.put(job)
        return self.jobs.qsize() + (1 if self.current else 0)

    def stop_all(self):
        drained = 0
        try:
            while True:
                self.jobs.get_nowait()
                drained += 1
        except queue.Empty:
            pass
        cur = self.current
        if cur:
            cur.cancel("user")
        return cur is not None, drained

    def run(self):
        while True:
            job = self.jobs.get()
            try:
                self.run_job(job)
            except Exception as e:
                log(f"worker error: {e!r}")
                self.bridge.tg.send(
                    self.chat_id, f"⚠️ bridge error: {e}",
                    message_thread_id=self.thread_id)
            finally:
                self.current = None
                self.bridge.save()

    def run_job(self, job):
        bridge, tg, cfg = self.bridge, self.bridge.tg, self.bridge.cfg
        live_chat = bridge.chat_state(self.chat_id, self.thread_id)
        prompt = job["prompt"]
        engine = job["engine"]
        key = (job["generation"], engine, job["cwd"], job["model"])
        context = self.contexts.setdefault(key, {
            "session_id": job["session_id"],
            "codex_session_id": job["codex_session_id"],
            "cursor_session_id": job.get("cursor_session_id"),
            "kimi_continue": job["kimi_continue"],
        })
        chat = {
            "cwd": job["cwd"],
            "engine": engine,
            "model": job["model"],
            **context,
        }
        run = ENGINES.get(engine, ClaudeRun)(cfg, chat, prompt)
        self.current = run
        self.current_started = time.time()
        self.current_prompt = prompt
        log(f"{engine} prompt ({chat['cwd']}): {prompt[:120]}")

        actions = deque(maxlen=PROGRESS_ACTIONS)
        n_actions = [0]
        progress_id = tg.send(
            self.chat_id, f"⏳ starting {engine}…", reply_markup=STOP_KB,
            message_thread_id=self.thread_id)
        last_edit = [time.time()]
        edit_lock = threading.Lock()

        def render():
            head = (f"⏳ {fmt_elapsed(time.time() - self.current_started)}"
                    f" · {engine}"
                    f" · {os.path.basename(chat['cwd'])}"
                    f" · {n_actions[0]} actions"
                    + (f" · {chat['model']}"
                       if engine == "claude" and chat.get("model") else ""))
            return head + "\n" + "\n".join(actions)

        def push_edit():
            last_edit[0] = time.time()
            tg.edit(self.chat_id, progress_id, render(),
                    reply_markup=STOP_KB)
            tg.typing(self.chat_id, message_thread_id=self.thread_id)

        def on_event(desc):
            # Sibling of deliver_result: the ticker also ships agent text to
            # Telegram — tool arguments via describe_tool, and a 60-char
            # slice of every assistant turn (kimi streams raw stdout here).
            # A key quoted in a tool argument leaves through this message,
            # not the result. Redact rather than refuse: killing the progress
            # display would make the bridge feel broken.
            n_actions[0] += 1
            actions.append(redact_secrets(desc))
            with edit_lock:
                if progress_id and time.time() - last_edit[0] >= EDIT_INTERVAL:
                    push_edit()

        done = threading.Event()

        def ticker():
            # keep the elapsed clock moving even during long silent tools
            while not done.wait(10):
                with edit_lock:
                    if progress_id and time.time() - last_edit[0] >= 9:
                        push_edit()

        threading.Thread(target=ticker, daemon=True).start()
        try:
            result = run.execute(on_event)
        finally:
            done.set()
        update_context_from_run(context, chat, engine, result)
        # A /new, /cd, /repo, /engine, /model, or /attach issued while this
        # job ran invalidates its right to update the live chat session.
        with bridge.state_lock:
            commit_context_if_current(live_chat, job, context)
        bridge.record_usage(result, n_actions[0])

        took = fmt_elapsed(time.time() - self.current_started)
        if progress_id:
            if result["ok"]:
                summary = f"✅ done · {took} · {n_actions[0]} actions"
                if result.get("cost") is not None:
                    summary += f" · ${result['cost']:.2f}"
            else:
                summary = f"⚠️ ended · {took}"
            tg.edit(self.chat_id, progress_id, summary)  # keyboard drops off
        bridge.deliver_result(
            self.chat_id, result["text"], message_thread_id=self.thread_id)


# ---------------------------------------------------------------- handlers

HELP = """LiquiLens agent hub on the host Mac (v7).

One Telegram poller. Telegram and Nicegram show the same bot. Terminal,
Cursor, Codex, and Grok attach with `ll-hub` instead of a second poller.

Just type anything and the selected engine runs it in the current repo.
Each tool call streams into a live progress message with a 🛑 stop button.
Send a photo/document/voice note with a caption: saved to this Mac,
caption becomes the prompt. FORWARDED files and forwarded text are held:
their words are someone else's, so they run only on /file <instruction>
or a tap of the run button.

Commands (answer instantly, even while the engine is working):
/stop          kill the current run + clear the queue
/status        cwd, git branch, engine, session, model, queue, uptime
/clients       Telegram, Nicegram, and the local ll-hub CLI
/new           fresh session
/attach        continue the latest Claude or Cursor session in this cwd
/engine        tap to pick claude, codex, kimi, cursor, or grok
/cd <path>     set working directory for this chat
/repo <name>   shortcut for /cd ~/dev/<name>
/repos         tap-to-switch repo buttons
/model         tap-to-pick model (fable 5 / opus / sonnet / haiku)
/cost          today + last-7-days spend
/file <what>   act on the last file sent (needed for forwarded files)
/get <path>    send me a file from the Mac
/sh <cmd>      raw shell command (bypasses the engine)
/log [n]       tail the bridge log
/help          this message

Messages sent while an engine is busy are queued and run in order.
Long results arrive as a summary + attached .md file.
From a terminal on this Mac: ll-hub send "fix the test"."""


class Bridge:
    def __init__(self, cfg):
        self.cfg = cfg
        self.tg = Telegram(cfg["bot_token"])
        self.state = self._load_state()
        self.state_lock = threading.RLock()
        self.started = time.time()
        self.workers = {}
        self.bot_username = None
        self.topics_enabled = None
        self.webhook_clear = None
        self.last_poll_at = 0
        self.poller_running = False
        self.hub = None

    @staticmethod
    def _load_state():
        try:
            raw = read_private(STATE_PATH)
        except FileNotFoundError:
            return {"chats": {}}
        state = strict_json_loads(raw, STATE_PATH)
        if not isinstance(state, dict) or not isinstance(state.get("chats"), dict):
            raise ValueError("state.json must contain a chats object")
        offset = state.get("offset", 0)
        if (isinstance(offset, bool) or not isinstance(offset, int)
                or offset < 0):
            raise ValueError("state.json offset must be a nonnegative integer")
        if "usage" in state and not isinstance(state["usage"], dict):
            raise ValueError("state.json usage must be an object")
        return state

    def save(self):
        with self.state_lock:
            body = json.dumps(self.state, indent=2, sort_keys=True,
                              allow_nan=False) + "\n"
            atomic_private_write(STATE_PATH, body)

    def chat_state(self, chat_id, thread_id=None):
        with self.state_lock:
            chat = self.state["chats"].setdefault(
                conversation_key(chat_id, thread_id),
                {"session_id": None, "cwd": self.cfg["default_cwd"]})
            chat.setdefault("context_generation", 0)
            return chat

    def worker(self, chat_id, thread_id=None):
        key = (chat_id, thread_id)
        w = self.workers.get(key)
        if w is None or not w.is_alive():
            w = self.workers[key] = Worker(self, chat_id, thread_id)
            w.start()
        return w

    def record_usage(self, result, n_actions):
        with self.state_lock:
            day = time.strftime("%Y-%m-%d")
            u = self.state.setdefault("usage", {}).setdefault(
                day, {"cost": 0.0, "runs": 0, "actions": 0})
            u["runs"] += 1
            u["actions"] += n_actions
            if result.get("cost"):
                u["cost"] += result["cost"]

    def deliver_result(self, chat_id, raw, message_thread_id=None):
        """Short results as rendered HTML; long ones as head + .md file."""
        # Scanned before anything is sent AND before the .md is written, so
        # neither the inline reply, the head snippet, nor the auto-attached
        # file can carry a credential out. This is the injection surface: the
        # agent runs with bypassPermissions and can read ~/.ssh, the vault and
        # the gh token, so hostile text in anything it reads only has to get
        # a value into the answer. Refuse, and name the class, never the value.
        classes = scan_secrets(raw)
        if classes:
            log(f"refused to deliver result: matched {', '.join(classes)}")
            self.tg.send(
                chat_id,
                "⛔️ refused to send this result: it contains something "
                "shaped like credential material (" + ", ".join(classes)
                + "). An upload to Telegram cannot be recalled, so nothing "
                "was sent and nothing was written to the outbox. Read it on "
                "the Mac, or ask again for output that does not quote the "
                "secret.", message_thread_id=message_thread_id)
            return
        if len(raw) <= LONG_RESULT:
            rendered = md_to_html(raw)
            if len(rendered) <= MAX_MSG:
                self.tg.send_html(
                    chat_id, rendered, raw,
                    message_thread_id=message_thread_id)
            else:
                self.tg.send(
                    chat_id, raw, message_thread_id=message_thread_id)
            return
        ensure_private_dir(OUTBOX_DIR)
        fd, path = tempfile.mkstemp(
            prefix=f"result-{time.strftime('%H%M%S')}-", suffix=".md",
            dir=OUTBOX_DIR)
        try:
            os.fchmod(fd, PRIVATE_FILE_MODE)
            with os.fdopen(fd, "w", encoding="utf-8", closefd=False) as handle:
                handle.write(raw)
                handle.flush()
                os.fsync(fd)
        finally:
            os.close(fd)
        head = raw[:2500].rsplit("\n", 1)[0]
        self.tg.send(
            chat_id, head + "\n\n… (full output attached)",
            message_thread_id=message_thread_id)
        try:
            self.tg.send_document(
                chat_id, path, "full output",
                message_thread_id=message_thread_id)
        except Exception as e:
            log(f"result attach failed: {e}")
            self.tg.send(
                chat_id, raw, message_thread_id=message_thread_id)

    # ------------------------------------------------------------ commands

    def handle(self, chat_id, msg):
        text = msg.get("text") or ""
        stripped = text.strip()
        thread_id = message_thread_id(msg)
        chat = self.chat_state(chat_id, thread_id)
        w = self.worker(chat_id, thread_id)

        def reply(body, reply_markup=None):
            return self.tg.send(
                chat_id, body, reply_markup=reply_markup,
                message_thread_id=thread_id)

        if msg.get("document") or msg.get("photo") or msg.get("voice") \
                or msg.get("audio"):
            threading.Thread(target=self._handle_file,
                             args=(chat_id, msg, w), daemon=True).start()
        elif stripped and is_forwarded(msg):
            # Same defect as a forwarded caption, one message type over: this
            # text is a stranger's. It is intercepted HERE, above the command
            # dispatch, not below it — a forwarded "/sh curl … | sh" reaching
            # the /sh branch would run their shell line, which is worse than
            # running their prompt. Held behind one tap, the owner's own act.
            chat["pending_forward"] = stripped
            reply(
                "📨 forwarded text held — it was written by someone else, so "
                "I did not run it as a prompt or a command.\n\n"
                + stripped[:1200],
                reply_markup=kb([[("▶️ run it as a prompt", "fwd:run")]]))
        elif stripped in ("/start", "/help"):
            reply(HELP)
        elif stripped == "/stop":
            killed, drained = w.stop_all()
            bits = []
            if killed:
                bits.append("killed current run")
            if drained:
                bits.append(f"dropped {drained} queued")
            reply("🛑 " + (", ".join(bits) or "nothing running"))
        elif stripped == "/new":
            with self.state_lock:
                advance_context(chat)
                chat["session_id"] = None
                chat["codex_session_id"] = None
                chat["cursor_session_id"] = None
                chat.pop("kimi_continue", None)
            reply("🆕 Fresh session. Cwd: " + chat["cwd"])
        elif stripped == "/attach":
            engine = chat.get("engine", "claude")
            with self.state_lock:
                advance_context(chat)
                if engine == "cursor":
                    chat["cursor_session_id"] = CONTINUE
                    chat["engine"] = "cursor"
                else:
                    chat["session_id"] = CONTINUE
                    chat["engine"] = "claude"
            target = "Cursor" if engine == "cursor" else "Claude"
            reply("🔗 next message continues the MOST RECENT "
                  f"{target} session in {chat['cwd']}, including "
                  "one started in the terminal.")
        elif stripped.startswith("/engine"):
            arg = (stripped.split(None, 1)[1].strip().lower()
                   if " " in stripped else "")
            if arg in ENGINES:
                self._set_engine(chat_id, chat, arg, thread_id)
            else:
                reply("tap to pick engine:",
                      reply_markup=kb([[("🤖 claude", "engine:claude"),
                                        ("🧭 codex", "engine:codex")],
                                       [("🌙 kimi", "engine:kimi"),
                                        ("🖱️ cursor", "engine:cursor")],
                                       [("⚡ grok", "engine:grok")]]))
        elif stripped == "/status":
            reply(self._status_text(chat, w))
        elif stripped == "/clients":
            reply(self._clients_text())
        elif stripped.startswith("/cd ") or stripped.startswith("/repo "):
            arg = stripped.split(None, 1)[1].strip()
            path = (os.path.expanduser(arg) if stripped.startswith("/cd ")
                    else os.path.expanduser(f"~/dev/{arg}"))
            self._switch_dir(chat_id, chat, path, thread_id)
        elif stripped == "/repos":
            root = os.path.expanduser("~/dev")
            dirs = sorted(d for d in os.listdir(root)
                          if os.path.isdir(os.path.join(root, d))
                          and not d.startswith("."))
            rows = [[(d, f"repo:{d}") for d in dirs[i:i + 2]]
                    for i in range(0, len(dirs), 2)]
            reply("tap to switch repo:", reply_markup=kb(rows[:50]))
        elif stripped.startswith("/model"):
            arg = (stripped.split(None, 1)[1].strip()
                   if " " in stripped else "")
            if arg:
                self._set_model(chat_id, chat, arg, thread_id)
            else:
                reply("tap to pick model:", reply_markup=kb(
                    [[(m, f"model:{m}") for m in MODELS]]))
        elif stripped == "/cost":
            reply(self._cost_text())
        elif stripped.startswith("/get "):
            arg = stripped[5:].strip()
            path = os.path.expanduser(arg)
            if not os.path.isabs(path):
                path = os.path.join(chat["cwd"], path)
            if is_sensitive(path):
                reply("refused: that path looks like credential material, "
                      "and an upload to Telegram cannot be recalled. "
                      "Read it over /sh if you really mean to.")
            else:
                threading.Thread(target=self._send_file,
                                 args=(chat_id, path, thread_id),
                                 daemon=True).start()
        elif stripped.startswith("/sh "):
            threading.Thread(target=self._run_sh,
                             args=(chat_id, chat["cwd"], stripped[4:],
                                   thread_id),
                             daemon=True).start()
        elif stripped.startswith("/log"):
            arg = stripped.split(None, 1)[1] if " " in stripped else "30"
            n = min(max(int(arg), 1), 500) if arg.isdigit() else 30
            try:
                lines = read_private(LOG_PATH).decode(
                    "utf-8", errors="replace").splitlines(keepends=True)
                tail = "".join(lines[-n:])
            except OSError as e:
                tail = str(e)
            tail = tail.replace(self.cfg["bot_token"], "***TOKEN***")
            # The log records prompts and shell lines, so it inherits whatever
            # was in them. Redacted, not refused: a single secret-shaped
            # string in bridge.log would otherwise break /log permanently,
            # and a debugging tool that refuses to work gets removed.
            reply(redact_secrets(tail) or "(empty)")
        elif stripped.startswith("/file"):
            instruction = (stripped.split(None, 1)[1].strip()
                           if " " in stripped else "")
            path = chat.get("pending_file")
            if not path:
                reply("no file waiting; send one first.")
            elif not instruction:
                reply(f"📎 waiting: {path}\nsay what to do with it: "
                      "/file summarise the tables")
            else:
                w.submit(f"{instruction}\n\n(The user attached a file, "
                         f"saved at: {path})")
        elif stripped:
            pos = w.submit(stripped)
            if pos > 1:
                reply(f"📥 queued (position {pos}; /stop cancels)")
        self.save()

    def handle_callback(self, cq):
        """Inline-button taps. Caller has already verified the sender."""
        data = cq.get("data") or ""
        callback_message = cq.get("message") or {}
        chat_id = (callback_message.get("chat") or {}).get("id")
        if chat_id is None:
            self.tg.answer_callback(cq["id"])
            return
        thread_id = message_thread_id(callback_message)
        chat = self.chat_state(chat_id, thread_id)
        if data == "fwd:run":
            pending = chat.pop("pending_forward", None)
            if pending:
                self.worker(chat_id, thread_id).submit(pending)
            self.tg.answer_callback(cq["id"],
                                    "running" if pending else "nothing held")
            self.save()
            return
        if data == "stop":
            killed, drained = self.worker(chat_id, thread_id).stop_all()
            note = "stopping…" if killed else "nothing running"
            if drained:
                note += f" (+{drained} queued dropped)"
            self.tg.answer_callback(cq["id"], note)
        elif data.startswith("repo:"):
            self.tg.answer_callback(cq["id"])
            path = os.path.expanduser(f"~/dev/{data[5:]}")
            self._switch_dir(chat_id, chat, path, thread_id)
        elif data.startswith("model:"):
            self.tg.answer_callback(cq["id"])
            self._set_model(chat_id, chat, data[6:], thread_id)
        elif data.startswith("engine:"):
            self.tg.answer_callback(cq["id"])
            self._set_engine(chat_id, chat, data[7:], thread_id)
        else:
            self.tg.answer_callback(cq["id"])
        self.save()

    def _set_engine(self, chat_id, chat, name, thread_id=None):
        with self.state_lock:
            if chat.get("engine", "claude") != name:
                advance_context(chat)
            chat["engine"] = name
        note = f"⚙️ engine: {name}"
        if name == "kimi":
            note += ("\nnote: /model applies to claude only; kimi uses its "
                     "own default model. Session continues per-directory "
                     "via kimi -c.")
        elif name == "codex":
            note += ("\nnote: Codex writes are limited to the selected Git "
                     "repo, but filesystem reads may be broader. It ignores "
                     "custom user configuration unless enabled in "
                     "config.json.")
        elif name == "cursor":
            note += ("\nnote: Cursor agent runs with --trust"
                     + (" and --force" if self.cfg.get("cursor_force", True)
                        else "")
                     + ". MCP servers are not auto-approved.")
        elif name == "grok":
            note += ("\nnote: Grok is one-shot; /model maps to grok -m. "
                     "There is no resume flag on this CLI.")
        self.tg.send(chat_id, note, message_thread_id=thread_id)

    def _switch_dir(self, chat_id, chat, path, thread_id=None):
        if os.path.isdir(path):
            with self.state_lock:
                advance_context(chat)
                chat["cwd"] = path
                chat["session_id"] = None  # sessions are per-project
                chat["codex_session_id"] = None
                chat["cursor_session_id"] = None
                chat.pop("kimi_continue", None)
            g = git_info(path)
            note = f"📁 cwd -> {path} (fresh session)"
            if g:
                note += f"\n🌿 {g}"
            self.tg.send(chat_id, note, message_thread_id=thread_id)
        else:
            self.tg.send(chat_id, f"❌ not a directory: {path}",
                         message_thread_id=thread_id)

    def _set_model(self, chat_id, chat, arg, thread_id=None):
        with self.state_lock:
            advance_context(chat)
            if arg in ("off", "default"):
                chat.pop("model", None)
            else:
                chat["model"] = arg
        if arg in ("off", "default"):
            self.tg.send(chat_id, "🧠 model: default",
                         message_thread_id=thread_id)
        else:
            self.tg.send(chat_id, f"🧠 model: {arg} (applies to next run)",
                         message_thread_id=thread_id)

    def _status_text(self, chat, w):
        up = int(time.time() - self.started)
        lines = []
        if w.current is not None:
            lines.append(f"🏃 BUSY "
                         f"{fmt_elapsed(time.time() - w.current_started)}"
                         f" on: {w.current_prompt[:80]}")
        else:
            lines.append("💤 idle")
        lines.append(f"cwd: {chat['cwd']}")
        g = git_info(chat["cwd"])
        if g:
            lines.append(f"git: {g}")
        engine = chat.get("engine", "claude")
        sid = (chat.get("codex_session_id") if engine == "codex"
               else chat.get("cursor_session_id") if engine == "cursor"
               else chat.get("session_id"))
        lines += [f"engine: {chat.get('engine', 'claude')}",
                  f"session: "
                  f"{'continue-latest' if sid == CONTINUE else sid or 'none'}",
                  f"model: {chat.get('model') or 'default'}",
                  f"queue: {w.jobs.qsize()} waiting",
                  f"bridge uptime: {up // 3600}h {(up % 3600) // 60}m"]
        return "\n".join(lines)

    def _cost_text(self):
        usage = self.state.get("usage", {})
        if not usage:
            return "no runs recorded yet"
        days = sorted(usage)[-7:]
        lines = ["last 7 days:"]
        week = 0.0
        for d in days:
            u = usage[d]
            week += u["cost"]
            lines.append(f"{d}: ${u['cost']:.2f} · {u['runs']} runs "
                         f"· {u['actions']} actions")
        total = sum(u["cost"] for u in usage.values())
        lines.append(f"7-day: ${week:.2f} · all-time: ${total:.2f}")
        return "\n".join(lines)

    def _handle_file(self, chat_id, msg, w):
        thread_id = message_thread_id(msg)
        name_hint = None
        try:
            if msg.get("document"):
                media = msg["document"]
                file_id = media["file_id"]
                name_hint = media.get("file_name")
            elif msg.get("photo"):     # list of sizes, last is largest
                file_id = msg["photo"][-1]["file_id"]
                name_hint = "photo.jpg"
            elif msg.get("voice"):
                file_id = msg["voice"]["file_id"]
                name_hint = "voice.ogg"
            else:
                media = msg["audio"]
                file_id = media["file_id"]
                name_hint = media.get("file_name") or "audio.bin"
            path = self.tg.download(file_id, INBOX_DIR, name_hint=name_hint)
        except Exception as e:
            self.tg.send(chat_id, f"⚠️ file download failed: {e}",
                         message_thread_id=thread_id)
            return
        caption = (msg.get("caption") or "").strip()
        chat = self.chat_state(chat_id, thread_id)
        chat["pending_file"] = path
        forwarded = is_forwarded(msg)
        log(f"file received -> {path} (forwarded={forwarded}, "
            f"caption: {caption[:80]})")
        if forwarded:
            # A forwarded caption was written by whoever posted the original,
            # not by the owner. Auto-submitting it handed an unvetted stranger
            # a prompt on an agent running with bypassPermissions. The file is
            # still saved; acting on it now takes an explicit command, which
            # is the step that turns someone else's text into her instruction.
            self.tg.send(
                chat_id,
                f"📎 saved (forwarded): {path}\n\nIts caption was written by "
                "whoever posted it, so I did not run it as a prompt. Send "
                "/file <what to do> to act on it."
                + (f"\n\nCaption was: {caption[:300]}" if caption else ""),
                message_thread_id=thread_id)
        elif caption:
            w.submit(f"{caption}\n\n(The user attached a file, saved at: "
                     f"{path})")
        else:
            self.tg.send(chat_id,
                         f"📎 saved: {path}\nReply with what to do with "
                         "it, or send /file <what to do>.",
                         message_thread_id=thread_id)
        self.save()

    def _send_file(self, chat_id, path, thread_id=None):
        resolved = os.path.realpath(path)
        if not os.path.isfile(resolved):
            self.tg.send(chat_id, f"❌ not a file: {path}",
                         message_thread_id=thread_id)
            return
        # Checked here, not only in the /get branch, because this is also the
        # auto-attach path for any agent result over the inline size limit.
        # An agent that has been steered by hostile text in something it read
        # reaches Telegram through here without passing /get at all.
        if is_sensitive(resolved):
            log(f"refused to send sensitive path: {resolved}")
            self.tg.send(chat_id,
                         "refused: that file looks like credential material, "
                         "and an upload to Telegram cannot be recalled.",
                         message_thread_id=thread_id)
            return
        size = os.path.getsize(resolved)
        if size > MAX_UPLOAD:
            self.tg.send(chat_id,
                         f"❌ too big for Telegram ({size >> 20}MB > 50MB)",
                         message_thread_id=thread_id)
            return
        try:
            self.tg.send_document(
                chat_id, resolved, message_thread_id=thread_id)
        except Exception as e:
            self.tg.send(chat_id, f"⚠️ send failed: {e}",
                         message_thread_id=thread_id)

    def _run_sh(self, chat_id, cwd, cmdline, thread_id=None):
        log(f"sh: {cmdline}")
        try:
            # shell=True is the feature here (/sh is a remote shell for the
            # owner); reachable only by whitelisted allowed_user_ids.
            p = subprocess.run(cmdline, shell=True, capture_output=True,
                               text=True, timeout=300, cwd=cwd)
            out = (p.stdout + p.stderr).strip() or "(no output)"
            # /sh is human-driven, not agent-reachable, so this is not the
            # injection path — but `cat` on the wrong file leaks just as
            # permanently. Redact, so the rest of the output still arrives.
            self.tg.send(chat_id, redact_secrets(out[:8000]),
                         message_thread_id=thread_id)
        except subprocess.TimeoutExpired:
            self.tg.send(chat_id, "⏱ shell command timed out (300s)",
                         message_thread_id=thread_id)

    # ------------------------------------------------------------ main loop

    def _clients_text(self):
        username = self.bot_username or "the work bot"
        return (
            "Same hub, three clients.\n\n"
            f"Telegram and Nicegram: @{username} in a private chat. "
            "Topics stay isolated. Command menu is published to both.\n"
            "CLI/API on this Mac: ll-hub status | send | engine | repo | stop\n"
            "Mission Control reads health.json only. It does not hold the "
            "bot token and cannot enqueue work.\n\n"
            "Never start a second getUpdates poller on this token. "
            "A 409 conflict means another process stole the bot."
        )

    def ensure_hub_dir(self, directory):
        ensure_private_dir(directory)

    def write_health(self):
        payload = hub_local.health_from_bridge(self)
        body = json.dumps(payload, indent=2, sort_keys=True,
                          allow_nan=False) + "\n"
        path = hub_local.health_path()
        ensure_private_dir(os.path.dirname(path))
        atomic_private_write(path, body)

    def _hub_chat(self, request):
        chat_id, thread_id = hub_local.select_hub_conversation(
            self.cfg, request)
        return chat_id, thread_id, self.chat_state(chat_id, thread_id)

    def hub_send(self, request):
        text = (request or {}).get("text")
        if not isinstance(text, str) or not text.strip():
            return {"ok": False, "error": "send requires a nonempty text field"}
        if len(text) > 8000:
            return {"ok": False, "error": "send text exceeds 8000 characters"}
        chat_id, thread_id, _chat = self._hub_chat(request)
        queued = self.worker(chat_id, thread_id).submit(text.strip())
        self.save()
        self.write_health()
        return {"ok": True, "queued": queued, "engine":
                self.chat_state(chat_id, thread_id).get("engine", "claude")}

    def hub_stop(self, request):
        chat_id, thread_id, _chat = self._hub_chat(request)
        killed, drained = self.worker(chat_id, thread_id).stop_all()
        self.write_health()
        return {"ok": True, "killed": killed, "drained": drained}

    def hub_set_engine(self, request):
        name = str((request or {}).get("name") or "").strip().lower()
        if name not in ENGINES:
            return {"ok": False, "error": "engine must be claude, codex, "
                    "kimi, cursor, or grok"}
        chat_id, thread_id, chat = self._hub_chat(request)
        self._set_engine(chat_id, chat, name, thread_id)
        self.save()
        self.write_health()
        return {"ok": True, "engine": name}

    def hub_set_cwd(self, request):
        if (request or {}).get("op") == "repo":
            name = str((request or {}).get("name") or "").strip()
            if not name or "/" in name or name in (".", ".."):
                return {"ok": False, "error": "repo name must be a ~/dev child"}
            path = os.path.expanduser(f"~/dev/{name}")
        else:
            raw = str((request or {}).get("path") or "").strip()
            if not raw:
                return {"ok": False, "error": "cd requires a path"}
            path = os.path.expanduser(raw)
        if not os.path.isdir(path):
            return {"ok": False, "error": f"not a directory: {path}"}
        chat_id, thread_id, chat = self._hub_chat(request)
        self._switch_dir(chat_id, chat, path, thread_id)
        self.save()
        self.write_health()
        return {"ok": True, "cwd": path}

    def publish_surface(self):
        try:
            info = self.tg.webhook_info()
            self.webhook_clear = webhook_is_clear(info)
            if not self.webhook_clear:
                log("FATAL: a Telegram webhook is set; getUpdates will starve")
                os._exit(1)
        except Exception as exc:
            log(f"webhook check failed: {exc}")
            self.webhook_clear = None
        try:
            me = self.tg.call("getMe", timeout=15)
            result = (me or {}).get("result") or {}
            self.bot_username = result.get("username")
            self.topics_enabled = bool(result.get("has_topics_enabled"))
        except Exception as exc:
            log(f"getMe failed: {exc}")
        try:
            self.tg.set_my_commands(BOT_COMMANDS)
        except Exception as exc:
            log(f"setMyCommands failed: {exc}")

    def _authorized(self, uid, chat):
        """Private 1-to-1 chat from a whitelisted user only."""
        return (chat.get("type") == "private"
                and uid is not None and chat.get("id") == uid
                and uid in set(self.cfg["allowed_user_ids"]))

    def run(self):
        offset = self.state.get("offset", 0)
        allowed = set(self.cfg["allowed_user_ids"])
        self.publish_surface()
        self.hub = hub_local.HubServer(self)
        try:
            self.hub.start()
        except Exception:
            self.write_health()
            raise
        self.poller_running = True
        self.write_health()
        log(f"bridge v7 up; allowed users: "
            f"{sorted(allowed) or 'NONE (setup mode)'}; "
            f"hub socket {hub_local.socket_path()}")
        while True:
            for upd in self.tg.get_updates(offset):
                offset = upd["update_id"] + 1
                self.state["offset"] = offset
                self.last_poll_at = int(time.time() * 1000)
                self.save()
                try:
                    self._dispatch(upd, allowed)
                except Exception as e:
                    log(f"dispatch error: {e!r}")
            self.last_poll_at = int(time.time() * 1000)
            try:
                self.write_health()
            except Exception as exc:
                log(f"health write failed: {exc}")

    def _dispatch(self, upd, allowed):
        cq = upd.get("callback_query")
        if cq:
            uid = (cq.get("from") or {}).get("id")
            cchat = (cq.get("message") or {}).get("chat") or {}
            if self._authorized(uid, cchat):
                self.handle_callback(cq)
            else:
                log(f"DENIED callback from {uid}")
                self.tg.answer_callback(cq.get("id", ""))
            return

        msg = upd.get("message") or {}
        chat = msg.get("chat") or {}
        chat_id = chat.get("id")
        user = msg.get("from") or {}
        uid = user.get("id")
        has_payload = (msg.get("text") or msg.get("document")
                       or msg.get("photo") or msg.get("voice")
                       or msg.get("audio"))
        if not has_payload or chat_id is None:
            return
        # 1-to-1 chats only: never execute from groups/channels,
        # even if every member were whitelisted.
        if chat.get("type") != "private" or chat_id != uid:
            log(f"DENIED non-private chat {chat_id} "
                f"(type={chat.get('type')}, from={uid})")
            return
        if not allowed:
            # setup mode: reveal sender's id so it can be whitelisted
            log(f"SETUP: message from user id {uid} "
                f"(@{user.get('username')}, {user.get('first_name')})")
            self.tg.send(
                chat_id,
                f"Setup mode. Your Telegram user id is {uid}.\n"
                f"Add it to allowed_user_ids in config.json and "
                f"restart the bridge.",
                message_thread_id=message_thread_id(msg))
            return
        if uid not in allowed:
            log(f"DENIED user {uid} ({user.get('username')}): "
                f"{str(msg.get('text'))[:80]}")
            return
        try:
            self.handle(chat_id, msg)
        except Exception as e:
            log(f"handle error: {e!r}")
            self.tg.send(chat_id, f"⚠️ bridge error: {e}",
                         message_thread_id=message_thread_id(msg))


# ---------------------------------------------------------------- main

def check(cfg):
    ok = True
    if not cfg.get("bot_token") or "PASTE" in cfg.get("bot_token", ""):
        print("✗ bot_token not set in config.json")
        ok = False
    else:
        print("✓ bot_token present")

    cli_checks = (
        ("claude", cfg["claude_bin"], ["--help"],
         ("--strict-mcp-config", "--setting-sources", "--no-chrome"), True),
        ("codex", cfg["codex_bin"], ["exec", "--help"],
         ("--ignore-user-config", "--ignore-rules", "--sandbox", "--json"), True),
        ("kimi", cfg["kimi_bin"], ["--help"],
         ("--prompt", "--output-format"), True),
        ("cursor", cfg["cursor_bin"], ["--help"],
         ("--print", "--output-format", "--trust", "--force"), False),
        ("grok", cfg["grok_bin"], ["--help"],
         ("--single", "--cwd", "--output-format"), False),
    )
    for label, binary, arguments, required, required_engine in cli_checks:
        if not os.path.isfile(binary) or not os.access(binary, os.X_OK):
            mark = "✗" if required_engine else "!"
            print(f"{mark} {label} binary missing: {binary}")
            if required_engine:
                ok = False
            continue
        try:
            proc = subprocess.run(
                [binary, *arguments], capture_output=True, text=True,
                timeout=15, check=False)
            help_text = proc.stdout + proc.stderr
        except (OSError, subprocess.TimeoutExpired) as exc:
            print(f"✗ {label} capability check failed: {exc}")
            if required_engine:
                ok = False
            continue
        missing = [flag for flag in required if flag not in help_text]
        if proc.returncode != 0 or missing:
            print(f"✗ {label} is missing required flags: {missing}")
            if required_engine:
                ok = False
        else:
            print(f"✓ {label} binary and automation flags: {binary}")
    if os.path.isdir(cfg["default_cwd"]):
        print(f"✓ default cwd: {cfg['default_cwd']}")
    else:
        print(f"✗ default cwd missing: {cfg['default_cwd']}")
        ok = False
    if cfg["allowed_user_ids"]:
        print(f"✓ allowed users: {cfg['allowed_user_ids']}")
    else:
        print("! allowed_user_ids empty -> bridge starts in SETUP MODE "
              "(replies with your user id, executes nothing)")
    if ok and cfg.get("bot_token") and "PASTE" not in cfg["bot_token"]:
        try:
            if cfg.get("force_ipv4"):
                force_ipv4()
            me = Telegram(cfg["bot_token"]).call("getMe", timeout=15)
            print(f"✓ Telegram API reachable, bot: "
                  f"@{me['result']['username']}")
            print("✓ Telegram private-topic mode: "
                  + ("enabled" if me["result"].get("has_topics_enabled")
                     else "available, not enabled"))
            webhook = Telegram(cfg["bot_token"]).webhook_info()
            if webhook_is_clear(webhook):
                print("✓ Telegram webhook is clear (getUpdates can run)")
            else:
                print("✗ a Telegram webhook is set; delete it or this Mac "
                      "will never see updates")
                ok = False
        except Exception as e:
            print(f"✗ Telegram API check failed: {e}")
            ok = False
    return ok


def main():
    os.umask(0o077)
    if sys.argv[1:2] == ["--render-launchd"]:
        if len(sys.argv) != 8:
            raise SystemExit(
                "usage: bridge.py --render-launchd TEMPLATE OUTPUT LABEL "
                "PYTHON BRIDGE_DIR HOME")
        render_launchd_plist(*sys.argv[2:])
        return
    if sys.argv[1:2] == ["cli"] or (
            sys.argv[1:2] and sys.argv[1] in (
                "status", "send", "engine", "repo", "cd", "stop", "help")):
        raise SystemExit(hub_local.cli_main(sys.argv[1:]))
    ensure_private_dir(INBOX_DIR)
    ensure_private_dir(OUTBOX_DIR)
    cfg = load_config()
    if "--check" in sys.argv:
        sys.exit(0 if check(cfg) else 1)
    if cfg.get("force_ipv4"):
        force_ipv4()
    Bridge(cfg).run()


if __name__ == "__main__":
    main()

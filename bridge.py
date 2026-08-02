#!/usr/bin/env python3
"""Telegram -> Claude Code bridge v4.

v4: model picker includes Fable 5 (claude-fable-5); second engine — Kimi
Code (/engine, per-directory -c continuity, errors surfaced with a renew
hint); /attach continues the latest Claude session in the cwd (terminal
handoff); elapsed-time ticker keeps the progress clock moving during
long silent tool calls.

Runs on this Mac. Polls Telegram (getUpdates long polling, outbound HTTPS
only, works behind NAT). Messages from the whitelisted user are fed to
headless Claude Code (`claude -p`); replies come back to the same chat.

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
import queue
import re
import signal
import subprocess
import socket
import sys
import threading
import time
import urllib.error
import urllib.parse
import urllib.request
import uuid
from collections import deque

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

MODELS = ["fable", "opus", "sonnet", "haiku", "default"]
MODEL_IDS = {"fable": "claude-fable-5"}   # friendly name -> CLI model id
CONTINUE = "__continue__"                 # session sentinel for /attach


# ---------------------------------------------------------------- utilities

_log_lock = threading.Lock()


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
            with open(LOG_PATH, "a") as f:
                f.write(line + "\n")
            if os.path.getsize(LOG_PATH) > 8 * 1024 * 1024:
                os.replace(LOG_PATH, LOG_PATH + ".1")
        except OSError:
            pass


# Credential-shaped paths /get refuses to upload. This is not a sandbox — /sh
# is a full shell by design — it stops one mistyped command from putting a
# private key or a token onto Telegram's servers, where it cannot be recalled.
_SENSITIVE_PARTS = ("/.ssh/", "/.gnupg/", "/.aws/", "/.kube/", "/.config/gh/",
                    "/private_vault/", "/.hermes/")
_SENSITIVE_NAMES = ("id_rsa", "id_ed25519", "id_ecdsa", "config.json",
                    "credentials", ".env", "known_hosts")
_SENSITIVE_SUFFIX = (".pem", ".key", ".p12", ".pfx", ".session", ".env")


def is_sensitive(path):
    """True if this path looks like credential material."""
    low = os.path.abspath(path).lower()
    name = os.path.basename(low)
    return (any(p in low for p in _SENSITIVE_PARTS)
            or name in _SENSITIVE_NAMES
            or name.startswith(".env")
            or low.endswith(_SENSITIVE_SUFFIX))


def force_ipv4():
    """This network black-holes some IPv6 routes; pin to IPv4."""
    real = socket.getaddrinfo

    def ipv4_only(host, port, family=0, *args, **kwargs):
        return real(host, port, socket.AF_INET, *args, **kwargs)

    socket.getaddrinfo = ipv4_only


def load_config():
    with open(CONFIG_PATH) as f:
        cfg = json.load(f)
    cfg.setdefault("allowed_user_ids", [])
    cfg.setdefault("default_cwd", os.path.expanduser("~/dev"))
    cfg.setdefault("claude_bin", os.path.expanduser("~/.local/bin/claude"))
    cfg.setdefault("kimi_bin", os.path.expanduser("~/.kimi-code/bin/kimi"))
    cfg.setdefault("claude_timeout_sec", 3600)
    cfg.setdefault("force_ipv4", True)
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
                    return json.load(resp)
            except urllib.error.HTTPError as e:
                try:
                    body = json.load(e)
                except Exception:
                    body = {}
                desc = body.get("description", f"HTTP {e.code}")
                if e.code == 429 and attempt < retries:
                    wait = (body.get("parameters") or {}).get("retry_after", 3)
                    log(f"telegram 429 on {method}; retrying in {wait}s")
                    time.sleep(wait + 0.5)
                    continue
                raise TelegramError(desc) from None
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
                log("FATAL: 409 Conflict — another poller holds this bot token; "
                    "exiting so only one survives")
                os._exit(1)
            backoff = min(5 * 2 ** (self._fails - 1), 300)
            log(f"getUpdates error ({self._fails}, retry in {backoff}s): {e}")
            time.sleep(backoff)
            return []

    def send(self, chat_id, text, reply_markup=None):
        """Plain-text send (chunked). Returns message_id of first chunk."""
        if not text.strip():
            text = "(empty response)"
        first_id = None
        chunks = [text[i:i + MAX_MSG] for i in range(0, len(text), MAX_MSG)]
        for chunk in chunks:
            params = {"chat_id": chat_id, "text": chunk}
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

    def send_html(self, chat_id, html_text, fallback_plain):
        """Single-message HTML send; falls back to plain chunks."""
        try:
            self.call("sendMessage",
                      {"chat_id": chat_id, "text": html_text,
                       "parse_mode": "HTML",
                       "disable_web_page_preview": "true"})
        except Exception as e:
            log(f"HTML send failed ({e}); falling back to plain")
            self.send(chat_id, fallback_plain)

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

    def typing(self, chat_id):
        try:
            self.call("sendChatAction",
                      {"chat_id": chat_id, "action": "typing"},
                      timeout=10, retries=0)
        except Exception:
            pass

    def download(self, file_id, dest_dir):
        """Fetch a Telegram file to dest_dir; returns local path."""
        r = self.call("getFile", {"file_id": file_id}, timeout=30)
        remote = r["result"]["file_path"]
        os.makedirs(dest_dir, exist_ok=True)
        name = os.path.basename(remote) or f"file-{file_id[:8]}"
        dest = os.path.join(dest_dir, f"{time.strftime('%H%M%S')}-{name}")
        url = f"https://api.telegram.org/file/bot{self.token}/{remote}"
        with urllib.request.urlopen(url, timeout=300) as resp, \
                open(dest, "wb") as f:
            while True:
                block = resp.read(65536)
                if not block:
                    break
                f.write(block)
        return dest

    def send_document(self, chat_id, path, caption=""):
        boundary = uuid.uuid4().hex
        with open(path, "rb") as f:
            file_data = f.read()
        parts = []
        for name, value in (("chat_id", str(chat_id)),
                            ("caption", caption[:1000])):
            parts.append(
                f"--{boundary}\r\nContent-Disposition: form-data; "
                f"name=\"{name}\"\r\n\r\n{value}\r\n".encode())
        parts.append(
            f"--{boundary}\r\nContent-Disposition: form-data; "
            f"name=\"document\"; filename=\"{os.path.basename(path)}\"\r\n"
            f"Content-Type: application/octet-stream\r\n\r\n".encode())
        parts.append(file_data)
        parts.append(f"\r\n--{boundary}--\r\n".encode())
        body = b"".join(parts)
        req = urllib.request.Request(
            f"{self.api}/sendDocument", data=body,
            headers={"Content-Type":
                     f"multipart/form-data; boundary={boundary}"})
        with urllib.request.urlopen(req, timeout=300) as resp:
            return json.load(resp)


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
            self.cfg["claude_bin"], "-p", self.prompt,
            "--output-format", "stream-json", "--verbose",
            "--permission-mode", "bypassPermissions",
            "--dangerously-skip-permissions",
        ]
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
                stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True,
                start_new_session=True)
        except FileNotFoundError:
            return {"sid": None, "ok": False,
                    "text": f"claude binary not found at "
                            f"{self.cfg['claude_bin']}"}

        self._stderr = ""
        proc = self.proc

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

    def execute(self, on_event):
        cmd = [self.cfg["kimi_bin"], "-p", self.prompt,
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


ENGINES = {"claude": ClaudeRun, "kimi": KimiRun}


# ---------------------------------------------------------------- worker

class Worker(threading.Thread):
    """Per-chat job runner: main loop stays free to answer commands."""

    def __init__(self, bridge, chat_id):
        super().__init__(daemon=True)
        self.bridge = bridge
        self.chat_id = chat_id
        self.jobs = queue.Queue()
        self.current = None          # ClaudeRun while busy
        self.current_started = None
        self.current_prompt = ""

    def submit(self, prompt):
        self.jobs.put(prompt)
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
            prompt = self.jobs.get()
            try:
                self.run_job(prompt)
            except Exception as e:
                log(f"worker error: {e!r}")
                self.bridge.tg.send(self.chat_id, f"⚠️ bridge error: {e}")
            finally:
                self.current = None
                self.bridge.save()

    def run_job(self, prompt):
        bridge, tg, cfg = self.bridge, self.bridge.tg, self.bridge.cfg
        chat = bridge.chat_state(self.chat_id)
        engine = chat.get("engine", "claude")
        run = ENGINES.get(engine, ClaudeRun)(cfg, chat, prompt)
        self.current = run
        self.current_started = time.time()
        self.current_prompt = prompt
        log(f"{engine} prompt ({chat['cwd']}): {prompt[:120]}")

        actions = deque(maxlen=PROGRESS_ACTIONS)
        n_actions = [0]
        progress_id = tg.send(self.chat_id, "⏳ starting claude…",
                              reply_markup=STOP_KB)
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
            tg.typing(self.chat_id)

        def on_event(desc):
            n_actions[0] += 1
            actions.append(desc)
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
        if result.get("sid"):
            chat["session_id"] = result["sid"]
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
        bridge.deliver_result(self.chat_id, result["text"])


# ---------------------------------------------------------------- handlers

HELP = """Claude Code bridge on the host Mac (v3).

Just type anything -> Claude Code runs it in the current repo; each tool
call streams into a live progress message with a 🛑 stop button.
Send a photo/document/voice note with a caption -> saved to this Mac,
caption becomes the prompt (Claude gets the file path).

Commands (answer instantly, even while the engine is working):
/stop          kill the current run + clear the queue
/status        cwd, git branch, engine, session, model, queue, uptime
/new           fresh session
/attach        continue the latest Claude session in this cwd —
               pick up exactly where the terminal left off
/engine        tap to pick claude 🤖 or kimi 🌙
/cd <path>     set working directory for this chat
/repo <name>   shortcut for /cd ~/dev/<name>
/repos         tap-to-switch repo buttons
/model         tap-to-pick model (fable 5 / opus / sonnet / haiku)
/cost          today + last-7-days spend
/get <path>    send me a file from the Mac
/sh <cmd>      raw shell command (bypasses Claude)
/log [n]       tail the bridge log
/help          this message

Messages sent while Claude is busy are queued and run in order.
Long results arrive as a summary + attached .md file.
Sessions resume across messages: "fix the test" then "now push it"."""


class Bridge:
    def __init__(self, cfg):
        self.cfg = cfg
        self.tg = Telegram(cfg["bot_token"])
        self.state = self._load_state()
        self.state_lock = threading.Lock()
        self.started = time.time()
        self.workers = {}

    @staticmethod
    def _load_state():
        try:
            with open(STATE_PATH) as f:
                return json.load(f)
        except (OSError, ValueError):
            return {"chats": {}}

    def save(self):
        with self.state_lock:
            tmp = STATE_PATH + ".tmp"
            with open(tmp, "w") as f:
                json.dump(self.state, f, indent=2)
            os.replace(tmp, STATE_PATH)

    def chat_state(self, chat_id):
        return self.state["chats"].setdefault(
            str(chat_id),
            {"session_id": None, "cwd": self.cfg["default_cwd"]})

    def worker(self, chat_id):
        w = self.workers.get(chat_id)
        if w is None or not w.is_alive():
            w = self.workers[chat_id] = Worker(self, chat_id)
            w.start()
        return w

    def record_usage(self, result, n_actions):
        day = time.strftime("%Y-%m-%d")
        u = self.state.setdefault("usage", {}).setdefault(
            day, {"cost": 0.0, "runs": 0, "actions": 0})
        u["runs"] += 1
        u["actions"] += n_actions
        if result.get("cost"):
            u["cost"] += result["cost"]

    def deliver_result(self, chat_id, raw):
        """Short results as rendered HTML; long ones as head + .md file."""
        if len(raw) <= LONG_RESULT:
            rendered = md_to_html(raw)
            if len(rendered) <= MAX_MSG:
                self.tg.send_html(chat_id, rendered, raw)
            else:
                self.tg.send(chat_id, raw)
            return
        os.makedirs(OUTBOX_DIR, exist_ok=True)
        path = os.path.join(OUTBOX_DIR,
                            f"result-{time.strftime('%H%M%S')}.md")
        with open(path, "w") as f:
            f.write(raw)
        head = raw[:2500].rsplit("\n", 1)[0]
        self.tg.send(chat_id, head + "\n\n… (full output attached)")
        try:
            self.tg.send_document(chat_id, path, "full output")
        except Exception as e:
            log(f"result attach failed: {e}")
            self.tg.send(chat_id, raw)  # fall back to chunks

    # ------------------------------------------------------------ commands

    def handle(self, chat_id, msg):
        text = msg.get("text") or ""
        stripped = text.strip()
        chat = self.chat_state(chat_id)
        w = self.worker(chat_id)

        if msg.get("document") or msg.get("photo") or msg.get("voice") \
                or msg.get("audio"):
            threading.Thread(target=self._handle_file,
                             args=(chat_id, msg, w), daemon=True).start()
        elif stripped in ("/start", "/help"):
            self.tg.send(chat_id, HELP)
        elif stripped == "/stop":
            killed, drained = w.stop_all()
            bits = []
            if killed:
                bits.append("killed current run")
            if drained:
                bits.append(f"dropped {drained} queued")
            self.tg.send(chat_id,
                         "🛑 " + (", ".join(bits) or "nothing running"))
        elif stripped == "/new":
            chat["session_id"] = None
            chat.pop("kimi_continue", None)
            self.tg.send(chat_id, "🆕 Fresh session. Cwd: " + chat["cwd"])
        elif stripped == "/attach":
            chat["session_id"] = CONTINUE
            chat["engine"] = "claude"
            self.tg.send(chat_id,
                         "🔗 next message continues the MOST RECENT "
                         f"Claude session in {chat['cwd']} — including "
                         "one started in the terminal.")
        elif stripped.startswith("/engine"):
            arg = (stripped.split(None, 1)[1].strip().lower()
                   if " " in stripped else "")
            if arg in ENGINES:
                self._set_engine(chat_id, chat, arg)
            else:
                self.tg.send(chat_id, "tap to pick engine:",
                             reply_markup=kb([[("🤖 claude", "engine:claude"),
                                               ("🌙 kimi", "engine:kimi")]]))
        elif stripped == "/status":
            self.tg.send(chat_id, self._status_text(chat, w))
        elif stripped.startswith("/cd ") or stripped.startswith("/repo "):
            arg = stripped.split(None, 1)[1].strip()
            path = (os.path.expanduser(arg) if stripped.startswith("/cd ")
                    else os.path.expanduser(f"~/dev/{arg}"))
            self._switch_dir(chat_id, chat, path)
        elif stripped == "/repos":
            root = os.path.expanduser("~/dev")
            dirs = sorted(d for d in os.listdir(root)
                          if os.path.isdir(os.path.join(root, d))
                          and not d.startswith("."))
            rows = [[(d, f"repo:{d}") for d in dirs[i:i + 2]]
                    for i in range(0, len(dirs), 2)]
            self.tg.send(chat_id, "tap to switch repo:",
                         reply_markup=kb(rows[:50]))
        elif stripped.startswith("/model"):
            arg = (stripped.split(None, 1)[1].strip()
                   if " " in stripped else "")
            if arg:
                self._set_model(chat_id, chat, arg)
            else:
                self.tg.send(chat_id, "tap to pick model:",
                             reply_markup=kb(
                                 [[(m, f"model:{m}") for m in MODELS]]))
        elif stripped == "/cost":
            self.tg.send(chat_id, self._cost_text())
        elif stripped.startswith("/get "):
            arg = stripped[5:].strip()
            path = os.path.expanduser(arg)
            if not os.path.isabs(path):
                path = os.path.join(chat["cwd"], path)
            if is_sensitive(path):
                self.tg.send(chat_id,
                             "refused: that path looks like credential material, "
                             "and an upload to Telegram cannot be recalled. "
                             "Read it over /sh if you really mean to.")
            else:
                threading.Thread(target=self._send_file,
                                 args=(chat_id, path), daemon=True).start()
        elif stripped.startswith("/sh "):
            threading.Thread(target=self._run_sh,
                             args=(chat_id, chat["cwd"], stripped[4:]),
                             daemon=True).start()
        elif stripped.startswith("/log"):
            arg = stripped.split(None, 1)[1] if " " in stripped else "30"
            n = int(arg) if arg.isdigit() else 30
            try:
                with open(LOG_PATH) as f:
                    tail = "".join(f.readlines()[-n:])
            except OSError as e:
                tail = str(e)
            tail = tail.replace(self.cfg["bot_token"], "***TOKEN***")
            self.tg.send(chat_id, tail or "(empty)")
        elif stripped:
            pos = w.submit(stripped)
            if pos > 1:
                self.tg.send(chat_id,
                             f"📥 queued (position {pos}; /stop cancels)")
        self.save()

    def handle_callback(self, cq):
        """Inline-button taps. Caller has already verified the sender."""
        data = cq.get("data") or ""
        chat_id = ((cq.get("message") or {}).get("chat") or {}).get("id")
        if chat_id is None:
            self.tg.answer_callback(cq["id"])
            return
        chat = self.chat_state(chat_id)
        if data == "stop":
            killed, drained = self.worker(chat_id).stop_all()
            note = "stopping…" if killed else "nothing running"
            if drained:
                note += f" (+{drained} queued dropped)"
            self.tg.answer_callback(cq["id"], note)
        elif data.startswith("repo:"):
            self.tg.answer_callback(cq["id"])
            path = os.path.expanduser(f"~/dev/{data[5:]}")
            self._switch_dir(chat_id, chat, path)
        elif data.startswith("model:"):
            self.tg.answer_callback(cq["id"])
            self._set_model(chat_id, chat, data[6:])
        elif data.startswith("engine:"):
            self.tg.answer_callback(cq["id"])
            self._set_engine(chat_id, chat, data[7:])
        else:
            self.tg.answer_callback(cq["id"])
        self.save()

    def _set_engine(self, chat_id, chat, name):
        chat["engine"] = name
        note = f"⚙️ engine: {name}"
        if name == "kimi":
            note += ("\nnote: /model applies to claude only; kimi uses its "
                     "own default model. Session continues per-directory "
                     "via kimi -c.")
        self.tg.send(chat_id, note)

    def _switch_dir(self, chat_id, chat, path):
        if os.path.isdir(path):
            chat["cwd"] = path
            chat["session_id"] = None  # sessions are per-project
            chat.pop("kimi_continue", None)
            g = git_info(path)
            note = f"📁 cwd -> {path} (fresh session)"
            if g:
                note += f"\n🌿 {g}"
            self.tg.send(chat_id, note)
        else:
            self.tg.send(chat_id, f"❌ not a directory: {path}")

    def _set_model(self, chat_id, chat, arg):
        if arg in ("off", "default"):
            chat.pop("model", None)
            self.tg.send(chat_id, "🧠 model: default")
        else:
            chat["model"] = arg
            self.tg.send(chat_id, f"🧠 model: {arg} (applies to next run)")

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
        sid = chat["session_id"]
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
        try:
            if msg.get("document"):
                file_id = msg["document"]["file_id"]
            elif msg.get("photo"):     # list of sizes, last is largest
                file_id = msg["photo"][-1]["file_id"]
            elif msg.get("voice"):
                file_id = msg["voice"]["file_id"]
            else:
                file_id = msg["audio"]["file_id"]
            path = self.tg.download(file_id, INBOX_DIR)
        except Exception as e:
            self.tg.send(chat_id, f"⚠️ file download failed: {e}")
            return
        caption = (msg.get("caption") or "").strip()
        log(f"file received -> {path} (caption: {caption[:80]})")
        if caption:
            w.submit(f"{caption}\n\n(The user attached a file, saved at: "
                     f"{path})")
        else:
            self.tg.send(chat_id,
                         f"📎 saved: {path}\nReply with what to do with "
                         "it, or resend with a caption.")

    def _send_file(self, chat_id, path):
        if not os.path.isfile(path):
            self.tg.send(chat_id, f"❌ not a file: {path}")
            return
        size = os.path.getsize(path)
        if size > 50 * 1024 * 1024:
            self.tg.send(chat_id,
                         f"❌ too big for Telegram ({size >> 20}MB > 50MB)")
            return
        try:
            self.tg.send_document(chat_id, path)
        except Exception as e:
            self.tg.send(chat_id, f"⚠️ send failed: {e}")

    def _run_sh(self, chat_id, cwd, cmdline):
        log(f"sh: {cmdline}")
        try:
            # shell=True is the feature here (/sh is a remote shell for the
            # owner); reachable only by whitelisted allowed_user_ids.
            p = subprocess.run(cmdline, shell=True, capture_output=True,
                               text=True, timeout=300, cwd=cwd)
            out = (p.stdout + p.stderr).strip() or "(no output)"
            self.tg.send(chat_id, out[:8000])
        except subprocess.TimeoutExpired:
            self.tg.send(chat_id, "⏱ shell command timed out (300s)")

    # ------------------------------------------------------------ main loop

    def _authorized(self, uid, chat):
        """Private 1-to-1 chat from a whitelisted user only."""
        return (chat.get("type") == "private"
                and uid is not None and chat.get("id") == uid
                and uid in set(self.cfg["allowed_user_ids"]))

    def run(self):
        offset = self.state.get("offset", 0)
        allowed = set(self.cfg["allowed_user_ids"])
        log(f"bridge v4 up; allowed users: "
            f"{sorted(allowed) or 'NONE (setup mode)'}")
        while True:
            for upd in self.tg.get_updates(offset):
                offset = upd["update_id"] + 1
                self.state["offset"] = offset
                self.save()
                try:
                    self._dispatch(upd, allowed)
                except Exception as e:
                    log(f"dispatch error: {e!r}")

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
            self.tg.send(chat_id,
                         f"Setup mode. Your Telegram user id is {uid}.\n"
                         f"Add it to allowed_user_ids in config.json and "
                         f"restart the bridge.")
            return
        if uid not in allowed:
            log(f"DENIED user {uid} ({user.get('username')}): "
                f"{str(msg.get('text'))[:80]}")
            return
        try:
            self.handle(chat_id, msg)
        except Exception as e:
            log(f"handle error: {e!r}")
            self.tg.send(chat_id, f"⚠️ bridge error: {e}")


# ---------------------------------------------------------------- main

def check(cfg):
    ok = True
    if not cfg.get("bot_token") or "PASTE" in cfg.get("bot_token", ""):
        print("✗ bot_token not set in config.json"); ok = False
    else:
        print("✓ bot_token present")
    if os.path.isfile(cfg["claude_bin"]) and os.access(cfg["claude_bin"],
                                                       os.X_OK):
        print(f"✓ claude binary: {cfg['claude_bin']}")
    else:
        print(f"✗ claude binary missing: {cfg['claude_bin']}"); ok = False
    if os.path.isdir(cfg["default_cwd"]):
        print(f"✓ default cwd: {cfg['default_cwd']}")
    else:
        print(f"✗ default cwd missing: {cfg['default_cwd']}"); ok = False
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
        except Exception as e:
            print(f"✗ Telegram API check failed: {e}"); ok = False
    return ok


def main():
    cfg = load_config()
    if "--check" in sys.argv:
        sys.exit(0 if check(cfg) else 1)
    if cfg.get("force_ipv4"):
        force_ipv4()
    Bridge(cfg).run()


if __name__ == "__main__":
    main()

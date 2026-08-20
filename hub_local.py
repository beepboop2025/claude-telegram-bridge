#!/usr/bin/env python3
"""Owner-only local CLI/API for the Telegram work bridge.

Telegram Bot API allows one getUpdates poller per token. This module does
not poll. It exposes the already-running launchd bridge over a mode-0600
Unix socket so terminal LLMs, Cursor, Codex, Grok, and Mission Control can
share the same worker queues. Results still land in the owner Telegram
chat, which Nicegram shows because it is a Telegram client, not a second
bot API.
"""

import json
import os
import socket
import stat
import sys
import threading
import time

HUB_SCHEMA = "liquilens-agent-hub-v1"
MAX_HUB_REQUEST = 64 * 1024
SOCKET_NAME = "hub.sock"
HEALTH_NAME = "health.json"
KNOWN_OPS = ("status", "send", "stop", "engine", "repo", "cd", "help")
KNOWN_CLIENTS = ("telegram", "nicegram", "cli")
ENGINE_LABELS = ("claude", "codex", "kimi", "cursor", "grok")


def hub_dir(home=None):
    root = home or os.path.expanduser("~")
    override = os.environ.get("LIQUILENS_HUB_DIR")
    if override:
        return os.path.realpath(override)
    return os.path.join(root, "Library", "Application Support",
                        "liquilens-agent-hub")


def socket_path(home=None):
    return os.path.join(hub_dir(home), SOCKET_NAME)


def health_path(home=None):
    return os.path.join(hub_dir(home), HEALTH_NAME)


def empty_health(detail="Hub health has not been published."):
    return {
        "schema": HUB_SCHEMA,
        "generatedAt": 0,
        "uptimeSec": 0,
        "botUsername": None,
        "topicsEnabled": None,
        "webhookClear": None,
        "socket": False,
        "lastPollAt": 0,
        "poller": "unknown",
        "engines": {name: "unknown" for name in ENGINE_LABELS},
        "busy": False,
        "queueDepth": 0,
        "activeEngine": None,
        "conversationCount": 0,
        "clients": list(KNOWN_CLIENTS),
        "detail": detail,
    }


def engine_presence(cfg):
    """ready/missing from configured binaries. Never probe the network."""
    mapping = (
        ("claude", "claude_bin"),
        ("codex", "codex_bin"),
        ("kimi", "kimi_bin"),
        ("cursor", "cursor_bin"),
        ("grok", "grok_bin"),
    )
    states = {}
    for name, key in mapping:
        path = cfg.get(key) if isinstance(cfg, dict) else None
        if (isinstance(path, str) and os.path.isfile(path)
                and os.access(path, os.X_OK)):
            states[name] = "ready"
        else:
            states[name] = "missing"
    return states


def health_from_bridge(bridge, extra=None):
    """Sanitized public snapshot. Token, user ids, and cwd stay out."""
    cfg = getattr(bridge, "cfg", {}) or {}
    now_ms = int(time.time() * 1000)
    busy = False
    queue = 0
    active = None
    for worker in getattr(bridge, "workers", {}).values():
        queue += worker.jobs.qsize()
        if worker.current is not None:
            busy = True
            queue += 1
            active = getattr(worker.current, "engine_name", None) or active
    chats = (getattr(bridge, "state", {}) or {}).get("chats") or {}
    hub = getattr(bridge, "hub", None)
    socket_ready = bool(hub is not None and hub.is_listening())
    payload = {
        "schema": HUB_SCHEMA,
        "generatedAt": now_ms,
        "uptimeSec": int(time.time() - getattr(bridge, "started", time.time())),
        "botUsername": getattr(bridge, "bot_username", None),
        "topicsEnabled": getattr(bridge, "topics_enabled", None),
        "webhookClear": getattr(bridge, "webhook_clear", None),
        "socket": socket_ready,
        "lastPollAt": int(getattr(bridge, "last_poll_at", 0) or 0),
        "poller": ("running" if getattr(bridge, "poller_running", False)
                   else "unknown"),
        "engines": engine_presence(cfg),
        "busy": busy,
        "queueDepth": queue,
        "activeEngine": active,
        "conversationCount": len(chats) if isinstance(chats, dict) else 0,
        "clients": list(KNOWN_CLIENTS),
        "detail": (
            "Owner-only hub. One Telegram poller. Local CLI shares it."
            if socket_ready else
            "DEGRADED: Telegram poller is running but the local Hub socket is not listening."
        ),
    }
    if extra:
        payload.update(extra)
    return sanitize_health(payload)


def sanitize_health(raw):
    """Drop anything a renderer or log should never see."""
    if not isinstance(raw, dict):
        return empty_health("Health document was not an object.")
    base = empty_health()
    if raw.get("schema") != HUB_SCHEMA:
        base["detail"] = "Health document used an unknown schema."
        return base
    username = raw.get("botUsername")
    if isinstance(username, str) and _safe_bot_username(username):
        base["botUsername"] = username
    for key in ("topicsEnabled", "webhookClear", "socket", "busy"):
        if isinstance(raw.get(key), bool):
            base[key] = raw[key]
    for key in ("generatedAt", "uptimeSec", "lastPollAt", "queueDepth",
                "conversationCount"):
        value = raw.get(key)
        if (not isinstance(value, bool) and isinstance(value, int)
                and value >= 0):
            base[key] = value
    if raw.get("poller") in ("running", "unknown"):
        base["poller"] = raw["poller"]
    engines = raw.get("engines")
    if isinstance(engines, dict):
        cleaned = {}
        for name in ENGINE_LABELS:
            state = engines.get(name)
            cleaned[name] = (state if state in ("ready", "missing", "error",
                                                "unknown")
                             else "unknown")
        base["engines"] = cleaned
    if raw.get("activeEngine") in ENGINE_LABELS:
        base["activeEngine"] = raw["activeEngine"]
    clients = raw.get("clients")
    if isinstance(clients, list):
        base["clients"] = [name for name in clients if name in KNOWN_CLIENTS]
    detail = raw.get("detail")
    if isinstance(detail, str):
        base["detail"] = detail.replace("\x00", "")[:240]
    return base


def _safe_bot_username(value):
    if value.startswith("@"):
        value = value[1:]
    return bool(value) and value.replace("_", "").isalnum() and 5 <= len(value) <= 32


def select_hub_conversation(cfg, request):
    """Choose the Telegram chat the local CLI should enqueue into.

    Default: the first allowed user id, main private chat (no topic).
    That is the same 1-to-1 chat Telegram and Nicegram already share.

    Owner hook: map CLI clients onto private-chat topics if you want
    Cursor, Codex, and Grok isolated without extra bots. Return
    (chat_id, thread_id_or_None).
    """
    allowed = cfg.get("allowed_user_ids") or []
    if not allowed:
        raise ValueError("allowed_user_ids is empty; CLI send is disarmed")
    requested = (request or {}).get("thread_id")
    thread_id = requested if (isinstance(requested, int)
                              and not isinstance(requested, bool)
                              and requested > 0) else None
    return allowed[0], thread_id


class HubServer(threading.Thread):
    """Accept one JSON request per connection. Never talks to Telegram."""

    def __init__(self, bridge, home=None):
        super().__init__(daemon=True, name="liquilens-hub-local")
        self.bridge = bridge
        self.home = home
        self._sock = None
        self._socket_identity = None
        self._stop_event = threading.Event()
        self._listening = threading.Event()

    def is_listening(self):
        sock = self._sock
        return (self._listening.is_set() and sock is not None
                and sock.fileno() >= 0)

    def start(self):
        """Bind synchronously so startup cannot publish a false-green socket."""
        if self._sock is not None or self._listening.is_set():
            raise RuntimeError("HubServer cannot be started more than once")
        self._bind_listener()
        try:
            super().start()
        except BaseException:
            self._close_listener()
            raise

    def _bind_listener(self):
        path = socket_path(self.home)
        directory = hub_dir(self.home)
        self.bridge.ensure_hub_dir(directory)
        if os.path.lexists(path):
            if os.path.islink(path) or not stat.S_ISSOCK(os.lstat(path).st_mode):
                raise OSError(f"refusing unsafe hub socket path: {path}")
            if _socket_accepts_connections(path):
                raise OSError(f"an active hub socket already owns: {path}")
            os.unlink(path)

        sock = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        identity = None
        try:
            sock.bind(path)
            bound = os.lstat(path)
            identity = (bound.st_dev, bound.st_ino)
            os.chmod(path, 0o600)
            sock.listen(16)
            sock.settimeout(1.0)
        except BaseException:
            sock.close()
            _unlink_socket_if_owned(path, identity)
            raise
        self._sock = sock
        self._socket_identity = identity
        self._listening.set()

    def stop(self):
        self._stop_event.set()
        self._close_listener()

    def run(self):
        sock = self._sock
        if sock is None or not self._listening.is_set():
            raise RuntimeError("HubServer accept loop started without a listener")
        try:
            while not self._stop_event.is_set():
                try:
                    conn, _ = sock.accept()
                except socket.timeout:
                    continue
                except OSError:
                    if self._stop_event.is_set():
                        break
                    raise
                threading.Thread(target=self._serve, args=(conn,),
                                 daemon=True).start()
        finally:
            self._close_listener()
            try:
                self.bridge.write_health()
            except Exception:
                pass

    def _close_listener(self):
        self._listening.clear()
        sock = self._sock
        self._sock = None
        if sock is not None:
            try:
                sock.close()
            except OSError:
                pass
        _unlink_socket_if_owned(socket_path(self.home), self._socket_identity)
        self._socket_identity = None

    def _serve(self, conn):
        try:
            raw = _read_request(conn)
            request = _parse_request(raw)
            response = self.dispatch(request)
        except Exception as exc:
            response = {"ok": False, "error": str(exc)[:240]}
        try:
            conn.sendall((json.dumps(response, allow_nan=False) + "\n").encode())
        except OSError:
            pass
        finally:
            try:
                conn.close()
            except OSError:
                pass

    def dispatch(self, request):
        op = request.get("op")
        if op == "status":
            return {"ok": True, "hub": health_from_bridge(self.bridge)}
        if op == "help":
            return {"ok": True, "help": CLI_HELP}
        if op == "send":
            return self.bridge.hub_send(request)
        if op == "stop":
            return self.bridge.hub_stop(request)
        if op == "engine":
            return self.bridge.hub_set_engine(request)
        if op in ("repo", "cd"):
            return self.bridge.hub_set_cwd(request)
        return {"ok": False, "error": f"unknown op: {op}"}


def _socket_accepts_connections(path):
    probe = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
    probe.settimeout(0.25)
    try:
        probe.connect(path)
        return True
    except (ConnectionRefusedError, FileNotFoundError):
        return False
    finally:
        probe.close()


def _unlink_socket_if_owned(path, identity):
    if identity is None:
        return
    try:
        current = os.lstat(path)
    except FileNotFoundError:
        return
    if not stat.S_ISSOCK(current.st_mode):
        return
    if identity is not None and (current.st_dev, current.st_ino) != identity:
        return
    try:
        os.unlink(path)
    except FileNotFoundError:
        pass


def _read_request(conn):
    chunks = []
    total = 0
    while True:
        piece = conn.recv(4096)
        if not piece:
            break
        total += len(piece)
        if total > MAX_HUB_REQUEST:
            raise ValueError("hub request exceeds 64 KiB")
        chunks.append(piece)
        if b"\n" in piece:
            break
    return b"".join(chunks)


def _parse_request(raw):
    if not raw:
        raise ValueError("empty hub request")
    payload = json.loads(raw.decode("utf-8"), parse_constant=_reject_constant)
    if not isinstance(payload, dict):
        raise ValueError("hub request must be a JSON object")
    op = payload.get("op")
    if op not in KNOWN_OPS:
        raise ValueError("hub request op is missing or unknown")
    return payload


def _reject_constant(value):
    raise ValueError(f"nonfinite hub request value: {value}")


def call_hub(request, home=None, timeout=8):
    path = socket_path(home)
    if os.path.islink(path):
        raise OSError("hub socket is a symlink")
    raw = (json.dumps(request, allow_nan=False) + "\n").encode()
    if len(raw) > MAX_HUB_REQUEST:
        raise ValueError("hub request exceeds 64 KiB")
    sock = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
    sock.settimeout(timeout)
    try:
        sock.connect(path)
        sock.sendall(raw)
        chunks = []
        total = 0
        while True:
            piece = sock.recv(4096)
            if not piece:
                break
            total += len(piece)
            if total > MAX_HUB_REQUEST:
                raise ValueError("hub response exceeds 64 KiB")
            chunks.append(piece)
        body = b"".join(chunks).decode("utf-8")
        return json.loads(body, parse_constant=_reject_constant)
    finally:
        sock.close()


CLI_HELP = """ll-hub: talk to the LiquiLens Telegram/Nicegram work bridge.

The launchd service owns Telegram getUpdates. This CLI is a local client.

  ll-hub status
  ll-hub send "fix the test"
  ll-hub engine cursor
  ll-hub repo LiquiLens
  ll-hub cd ~/dev/seiche
  ll-hub stop
  ll-hub help

send/engine/repo land in the same private chat Telegram and Nicegram show.
Do not start a second bot poller.
"""


def cli_main(argv=None):
    args = list(sys.argv[1:] if argv is None else argv)
    if args[:1] == ["cli"]:
        args = args[1:]
    if not args or args[0] in ("help", "-h", "--help"):
        print(CLI_HELP)
        return 0
    command = args[0]
    try:
        if command == "status":
            response = call_hub({"op": "status"})
            print(json.dumps(response.get("hub") or response, indent=2,
                             sort_keys=True))
            return 0 if response.get("ok") else 1
        if command == "send":
            text = " ".join(args[1:]).strip()
            if not text:
                print("usage: ll-hub send <prompt>", file=sys.stderr)
                return 2
            response = call_hub({"op": "send", "text": text})
        elif command == "engine":
            if len(args) < 2:
                print("usage: ll-hub engine <claude|codex|kimi|cursor|grok>",
                      file=sys.stderr)
                return 2
            response = call_hub({"op": "engine", "name": args[1]})
        elif command == "repo":
            if len(args) < 2:
                print("usage: ll-hub repo <name-under-~/dev>", file=sys.stderr)
                return 2
            response = call_hub({"op": "repo", "name": args[1]})
        elif command == "cd":
            if len(args) < 2:
                print("usage: ll-hub cd <path>", file=sys.stderr)
                return 2
            response = call_hub({"op": "cd", "path": args[1]})
        elif command == "stop":
            response = call_hub({"op": "stop"})
        else:
            print(f"unknown command: {command}", file=sys.stderr)
            print(CLI_HELP, file=sys.stderr)
            return 2
    except (OSError, ValueError) as exc:
        print(f"hub unreachable: {exc}", file=sys.stderr)
        print("Is com.beepboop2025.claude-telegram-bridge running?",
              file=sys.stderr)
        return 1
    print(json.dumps(response, indent=2, sort_keys=True))
    return 0 if response.get("ok") else 1


if __name__ == "__main__":
    raise SystemExit(cli_main())

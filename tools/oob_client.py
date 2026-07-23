#!/usr/bin/env python3
"""Out-of-band (OOB) interaction correlation for confirming BLIND vulnerabilities.

Confirms blind SSRF / blind XXE / blind RCE / blind SQLi (DNS/HTTP callback) by
proving the target reached a listener we control. Prefers interactsh-client when
present; otherwise runs a built-in, log-only HTTP catcher.

Usage: python3 /tools/oob_client.py <command> [args]

Commands:
  register                 Start a listener; print callback URL + token.
  poll <token>             Return captured interactions as JSON list.
  serve <token> <port>     (internal) Run the blocking HTTP catcher.
  stop <token>             Terminate the listener for a token.

Outputs live under /work/loot/_oob/<token>.json (state) and .log (interactions).
STDLIB ONLY. The catcher only logs requests; it never executes anything.
"""

import hashlib
import json
import os
import re
import shutil
import signal
import socket
import subprocess
import sys
import threading
import time
from datetime import datetime, timezone
from http.server import BaseHTTPRequestHandler
from pathlib import Path
import socketserver

OOB_DIR = Path("/work/loot/_oob")
OOB_HOST = "kali-ai"  # reachable compose hostname other containers can call
PORT_MIN = 28000
PORT_MAX = 30000
# 1x1 transparent GIF returned to every caller.
PIXEL = (
    b"GIF89a\x01\x00\x01\x00\x80\x00\x00\x00\x00\x00\xff\xff\xff!"
    b"\xf9\x04\x01\x00\x00\x00\x00,\x00\x00\x00\x00\x01\x00\x01\x00"
    b"\x00\x02\x02D\x01\x00;"
)


def now_iso():
    return datetime.now(timezone.utc).isoformat()


def emit(obj):
    print(json.dumps(obj, indent=2))


def ensure_dir():
    OOB_DIR.mkdir(parents=True, exist_ok=True)


def state_path(token):
    return OOB_DIR / f"{token}.json"


def log_path(token):
    return OOB_DIR / f"{token}.log"


def make_token():
    seed = f"{time.time()}-{os.getpid()}-{os.urandom(8).hex()}"
    return hashlib.sha1(seed.encode()).hexdigest()[:20]


def free_port():
    """Find a free TCP port in the OOB range."""
    for port in range(PORT_MIN, PORT_MAX + 1):
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
            sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            try:
                sock.bind(("0.0.0.0", port))
                return port
            except OSError:
                continue
    return None


def write_state(token, data):
    ensure_dir()
    tmp = state_path(token).with_suffix(".json.tmp")
    tmp.write_text(json.dumps(data, indent=2))
    tmp.replace(state_path(token))


def read_state(token):
    path = state_path(token)
    if not path.exists():
        return None
    try:
        return json.loads(path.read_text())
    except (ValueError, OSError):
        return None


# --------------------------------------------------------------------------- #
# interactsh integration
# --------------------------------------------------------------------------- #
def register_interactsh():
    """Spawn interactsh-client, parse the generated OOB domain, persist state."""
    ensure_dir()
    token = make_token()
    out_file = OOB_DIR / f"{token}.interactsh.log"
    try:
        fh = open(out_file, "w")
        proc = subprocess.Popen(
            ["interactsh-client", "-json", "-o", str(out_file)],
            stdout=fh,
            stderr=subprocess.STDOUT,
        )
    except (OSError, ValueError) as exc:
        return {"status": "error", "detail": f"failed to spawn interactsh: {exc}"}

    domain = None
    deadline = time.time() + 15
    while time.time() < deadline and domain is None:
        time.sleep(0.5)
        try:
            text = out_file.read_text(errors="ignore")
        except OSError:
            text = ""
        match = re.search(r"([a-z0-9]+\.oast\.[a-z0-9.]+)", text, re.IGNORECASE)
        if match:
            domain = match.group(1)

    state = {
        "token": token,
        "mode": "interactsh",
        "pid": proc.pid,
        "domain": domain,
        "callback": f"http://{domain}/{token}" if domain else None,
        "interactsh_log": str(out_file),
        "created": now_iso(),
    }
    write_state(token, state)
    return {
        "status": "listening",
        "mode": "interactsh",
        "token": token,
        "oob_domain": domain,
        "callback_url": state["callback"],
    }


def poll_interactsh(state):
    interactions = []
    log_file = Path(state.get("interactsh_log", ""))
    if not log_file.exists():
        return interactions
    for line in log_file.read_text(errors="ignore").splitlines():
        line = line.strip()
        if not line.startswith("{"):
            continue
        try:
            evt = json.loads(line)
        except ValueError:
            continue
        interactions.append(
            {
                "source_ip": evt.get("remote-address") or evt.get("remote_address"),
                "protocol": evt.get("protocol"),
                "path": evt.get("q-type") or evt.get("full-id") or evt.get("raw-request", "")[:120],
                "ts": evt.get("timestamp") or now_iso(),
            }
        )
    return interactions


# --------------------------------------------------------------------------- #
# Built-in HTTP catcher (log-only)
# --------------------------------------------------------------------------- #
class _CatcherHandler(BaseHTTPRequestHandler):
    server_version = "kali-ai-oob/1.0"
    log_target = None  # set by the server factory

    def _record(self):
        try:
            entry = {
                "source_ip": self.client_address[0],
                "protocol": "http",
                "method": self.command,
                "path": self.path,
                "headers": {k: v for k, v in self.headers.items()},
                "ts": now_iso(),
            }
            if self.log_target:
                with open(self.log_target, "a") as fh:
                    fh.write(json.dumps(entry) + "\n")
        except Exception:
            # A catcher must never crash on a malformed request.
            pass

    def _respond_pixel(self):
        try:
            self.send_response(200)
            self.send_header("Content-Type", "image/gif")
            self.send_header("Content-Length", str(len(PIXEL)))
            self.end_headers()
            self.wfile.write(PIXEL)
        except Exception:
            pass

    # Log every method; never execute anything from the request.
    def do_GET(self):
        self._record()
        self._respond_pixel()

    def do_POST(self):
        self._drain_body()
        self._record()
        self._respond_pixel()

    def do_PUT(self):
        self._drain_body()
        self._record()
        self._respond_pixel()

    def do_HEAD(self):
        self._record()
        self._respond_pixel()

    def do_OPTIONS(self):
        self._record()
        self._respond_pixel()

    def do_DELETE(self):
        self._record()
        self._respond_pixel()

    def _drain_body(self):
        try:
            length = int(self.headers.get("Content-Length", 0))
            if 0 < length <= 65536:
                self.rfile.read(length)
        except (ValueError, OSError):
            pass

    def log_message(self, fmt, *args):
        # Silence default stderr access logging.
        return


class _ThreadingHTTPServer(socketserver.ThreadingMixIn, socketserver.TCPServer):
    allow_reuse_address = True
    daemon_threads = True


def serve_catcher(token, port):
    """Blocking HTTP catcher. Logs every request to <token>.log."""
    ensure_dir()
    handler = type("_H", (_CatcherHandler,), {"log_target": str(log_path(token))})
    try:
        httpd = _ThreadingHTTPServer(("0.0.0.0", int(port)), handler)
    except OSError as exc:
        emit({"status": "error", "detail": f"bind failed on {port}: {exc}"})
        return
    emit({"status": "serving", "token": token, "port": int(port)})
    try:
        httpd.serve_forever()
    except KeyboardInterrupt:
        pass
    finally:
        httpd.server_close()


def register_catcher():
    """Start the built-in catcher in a detached subprocess; return callback URL."""
    ensure_dir()
    token = make_token()
    port = free_port()
    if port is None:
        return {"status": "error", "detail": "no free OOB port available"}
    # Touch the log so poll() before any hit still works.
    log_path(token).touch()
    try:
        proc = subprocess.Popen(
            [sys.executable, os.path.abspath(__file__), "serve", token, str(port)],
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
        )
    except (OSError, ValueError) as exc:
        return {"status": "error", "detail": f"failed to start catcher: {exc}"}

    callback = f"http://{OOB_HOST}:{port}/{token}"
    state = {
        "token": token,
        "mode": "catcher",
        "pid": proc.pid,
        "port": port,
        "callback": callback,
        "created": now_iso(),
    }
    write_state(token, state)
    # Give the child a moment to bind.
    time.sleep(0.5)
    return {
        "status": "listening",
        "mode": "catcher",
        "token": token,
        "port": port,
        "callback_url": callback,
        "hint": "Inject this URL into SSRF/XXE/RCE payloads; poll to confirm a hit.",
    }


def poll_catcher(state):
    interactions = []
    path = log_path(state["token"])
    if not path.exists():
        return interactions
    for line in path.read_text(errors="ignore").splitlines():
        line = line.strip()
        if not line:
            continue
        try:
            evt = json.loads(line)
        except ValueError:
            continue
        interactions.append(
            {
                "source_ip": evt.get("source_ip"),
                "protocol": evt.get("protocol", "http"),
                "path": evt.get("path"),
                "method": evt.get("method"),
                "ts": evt.get("ts"),
            }
        )
    return interactions


# --------------------------------------------------------------------------- #
# Command dispatch
# --------------------------------------------------------------------------- #
def cmd_register():
    if shutil.which("interactsh-client"):
        result = register_interactsh()
        # If interactsh failed to yield a domain, fall back to the catcher.
        if result.get("status") == "listening" and result.get("oob_domain"):
            emit(result)
            return
    emit(register_catcher())


def cmd_poll(token):
    state = read_state(token)
    if state is None:
        emit({"status": "error", "detail": f"unknown token: {token}"})
        return
    if state.get("mode") == "interactsh":
        interactions = poll_interactsh(state)
    else:
        interactions = poll_catcher(state)
    emit(
        {
            "status": "ok",
            "token": token,
            "mode": state.get("mode"),
            "callback_url": state.get("callback"),
            "count": len(interactions),
            "confirmed": bool(interactions),
            "interactions": interactions,
        }
    )


def cmd_stop(token):
    state = read_state(token)
    if state is None:
        emit({"status": "error", "detail": f"unknown token: {token}"})
        return
    pid = state.get("pid")
    killed = False
    if pid:
        try:
            os.kill(int(pid), signal.SIGTERM)
            killed = True
        except (ProcessLookupError, PermissionError, ValueError):
            killed = False
    emit({"status": "stopped", "token": token, "pid": pid, "terminated": killed})


def usage():
    emit(
        {
            "status": "error",
            "detail": "usage: oob_client.py <register|poll|serve|stop> [args]",
        }
    )


def main():
    args = sys.argv[1:]
    if not args:
        usage()
        return
    cmd = args[0]
    try:
        if cmd == "register":
            cmd_register()
        elif cmd == "poll" and len(args) >= 2:
            cmd_poll(args[1])
        elif cmd == "serve" and len(args) >= 3:
            serve_catcher(args[1], args[2])
        elif cmd == "stop" and len(args) >= 2:
            cmd_stop(args[1])
        else:
            usage()
    except Exception as exc:  # never leak a stack trace to stdout
        emit({"status": "error", "detail": f"{type(exc).__name__}: {exc}"})


if __name__ == "__main__":
    main()

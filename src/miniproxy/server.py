"""MiniProxy process manager — start/stop/status for the mitmdump addon.

A standalone-friendly distillation of the lifecycle hardening the Riciplay
CLI's proxy_manager learned the hard way:

* the addon is resolved from the installed package (importlib.resources),
  never from the caller's cwd;
* mitmdump's listen port is passed explicitly (no silent fallback to a busy
  default);
* start() polls until the listener actually accepts TCP connections before
  returning — process-alive is not listener-ready;
* state (pid / port) lives under ``~/.miniproxy/`` so multiple users and
  worktrees don't fight over one pid file.
"""
from __future__ import annotations

import json
import os
import signal
import socket
import subprocess
import sys
import time
from pathlib import Path
from typing import Any, Optional

STATE_DIR = Path(os.environ.get("MINIPROXY_STATE_DIR", Path.home() / ".miniproxy"))
PID_FILE = STATE_DIR / "mitmdump.pid"
PORT_FILE = STATE_DIR / "mitmdump.port"
DEFAULT_PORT = 8080


def addon_path() -> Path:
    """Resolve the deployed addon script (proxy.py) inside the package."""
    from importlib.resources import files as _res_files

    return Path(str(_res_files("miniproxy.addon") / "proxy.py"))


def _read_pid() -> Optional[int]:
    try:
        return int(PID_FILE.read_text().strip())
    except (OSError, ValueError):
        return None


def _process_exists(pid: int) -> bool:
    try:
        os.kill(pid, 0)
        return True
    except OSError:
        return False


def _port_free(port: int) -> bool:
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        try:
            s.bind(("0.0.0.0", port))
            return True
        except OSError:
            return False


def _wait_listening(port: int, proc: subprocess.Popen, timeout: float = 8.0) -> bool:
    """Poll until the proxy accepts connections (or the process dies)."""
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        try:
            with socket.create_connection(("127.0.0.1", port), timeout=0.5):
                return True
        except OSError:
            if proc.poll() is not None:
                return False
            time.sleep(0.15)
    return False


def start(
    *,
    port: int = DEFAULT_PORT,
    db_path: Optional[str] = None,
    scope_hosts: Optional[list[str]] = None,
    out_of_scope: str = "skip",
    mitmdump_path: str = "mitmdump",
    extra_args: Optional[list[str]] = None,
) -> dict[str, Any]:
    """Start the interception proxy as a background subprocess.

    Args:
        port:          Explicit listen port (default 8080; must be free).
        db_path:       SQLite capture DB (default ``~/.miniproxy/proxy.db``).
        scope_hosts:   Optional capture-scope host list (``*.domain``
                       wildcards). Out-of-scope traffic is passed through
                       uncaptured (or 403-blocked, per *out_of_scope*).
        out_of_scope:  ``"skip"`` (default) or ``"block"``.
        mitmdump_path: Path to the mitmdump binary.
        extra_args:    Additional CLI flags forwarded to mitmdump.
    """
    pid = _read_pid()
    if pid is not None and _process_exists(pid):
        running_port = _read_port()
        return {
            "status": "already_running",
            "pid": pid,
            "port": running_port,
            "message": f"MiniProxy is already running (PID {pid}).",
        }

    script = addon_path()
    if not script.exists():
        return {"status": "error",
                "message": f"Addon not found at {script} (broken install?)."}

    port = int(port)
    if not _port_free(port):
        return {"status": "error",
                "message": f"Port {port} is already in use — pass --port."}

    STATE_DIR.mkdir(parents=True, exist_ok=True)
    db = str(db_path or os.environ.get("MINIPROXY_DB_PATH")
             or (STATE_DIR / "proxy.db"))

    env = os.environ.copy()
    env["MINIPROXY_DB_PATH"] = db
    hosts = [str(h).strip() for h in (scope_hosts or []) if str(h).strip()]
    if hosts:
        env["MINIPROXY_SCOPE"] = json.dumps(hosts)
        env["MINIPROXY_SCOPE_MODE"] = out_of_scope if out_of_scope in ("skip", "block") else "skip"
    else:
        env.pop("MINIPROXY_SCOPE", None)
        env.pop("MINIPROXY_SCOPE_MODE", None)

    cmd = (
        [mitmdump_path, "-s", str(script), "--set", "block_global=false",
         "--listen-port", str(port)]
        + (extra_args or [])
    )
    proc = subprocess.Popen(
        cmd, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
        env=env, start_new_session=True,
    )
    time.sleep(0.5)
    if proc.poll() is not None:
        return {"status": "error",
                "message": f"mitmdump exited immediately (code {proc.returncode}). "
                           "Is mitmproxy installed?"}
    if not _wait_listening(port, proc):
        return {"status": "error",
                "message": f"mitmdump did not bind :{port} within 8s (PID {proc.pid})."}

    PID_FILE.write_text(str(proc.pid))
    PORT_FILE.write_text(str(port))
    scope_note = (
        f", scope={len(hosts)} host(s) (out-of-scope: "
        f"{env.get('MINIPROXY_SCOPE_MODE', 'skip')})" if hosts else ""
    )
    return {
        "status": "started",
        "pid": proc.pid,
        "port": port,
        "db": db,
        "message": f"MiniProxy started on :{port} (PID {proc.pid}, db={db}{scope_note})",
    }


def stop() -> dict[str, Any]:
    pid = _read_pid()
    if pid is None:
        return {"status": "not_running", "message": "No PID file — nothing to stop."}
    if not _process_exists(pid):
        PID_FILE.unlink(missing_ok=True)
        PORT_FILE.unlink(missing_ok=True)
        return {"status": "not_running", "message": f"PID {pid} was already dead (cleaned)."}
    try:
        os.killpg(os.getpgid(pid), signal.SIGTERM)
    except (ProcessLookupError, PermissionError):
        pass
    PID_FILE.unlink(missing_ok=True)
    PORT_FILE.unlink(missing_ok=True)
    return {"status": "stopped", "message": f"MiniProxy terminated (PID {pid})."}


def _read_port() -> Optional[int]:
    try:
        return int(PORT_FILE.read_text().strip())
    except (OSError, ValueError):
        return None


def status() -> dict[str, Any]:
    pid = _read_pid()
    if pid is None or not _process_exists(pid):
        if pid is not None:
            PID_FILE.unlink(missing_ok=True)
            PORT_FILE.unlink(missing_ok=True)
        return {"status": "not_running", "pid": None, "port": None,
                "message": "MiniProxy is not running."}
    return {
        "status": "running",
        "pid": pid,
        "port": _read_port(),
        "db": os.environ.get("MINIPROXY_DB_PATH") or str(STATE_DIR / "proxy.db"),
        "message": f"MiniProxy is running (PID {pid}).",
    }

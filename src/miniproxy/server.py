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
DASH_PID_FILE = STATE_DIR / "dashboard.pid"
DASH_PORT_FILE = STATE_DIR / "dashboard.port"
DEFAULT_PORT = 8080
DEFAULT_DASH_PORT = 5000


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


def _pid_matches(pid: int, *needles: str) -> bool:
    """True if /proc/<pid>/cmdline contains every needle (pid-reuse guard).

    A stale pid file can point at a recycled PID belonging to a totally
    unrelated process; before trusting or killing it, verify the command
    line actually looks like ours. Non-Linux platforms (no /proc) skip
    the check and keep the old behavior.
    """
    try:
        with open(f"/proc/{pid}/cmdline", "rb") as fh:
            cmdline = fh.read().decode("utf-8", "replace")
    except OSError:
        return True  # cannot verify — assume match (macOS/Windows)
    lowered = cmdline.lower()
    return all(n.lower() in lowered for n in needles)


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


def _read_dash_pid() -> Optional[int]:
    try:
        return int(DASH_PID_FILE.read_text().strip())
    except (OSError, ValueError):
        return None


def _read_dash_port() -> Optional[int]:
    try:
        return int(DASH_PORT_FILE.read_text().strip())
    except (OSError, ValueError):
        return None


def start(
    *,
    port: int = DEFAULT_PORT,
    db_path: Optional[str] = None,
    scope_hosts: Optional[list[str]] = None,
    out_of_scope: str = "skip",
    mitmdump_path: str = "mitmdump",
    extra_args: Optional[list[str]] = None,
    dashboard: bool = True,
    dash_port: int = DEFAULT_DASH_PORT,
    with_dashboard: Optional[bool] = None,
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
        dashboard:     Also launch the web dashboard (default True) and
                       include its URL in the result. Capture is unchanged —
                       the dashboard only reads the same SQLite DB.
        dash_port:     Port for the web dashboard (default 5000).
    """
    pid = _read_pid()
    if pid is not None and _process_exists(pid) and _pid_matches(pid, "mitmdump"):
        running_port = _read_port()
        result = {
            "status": "already_running",
            "pid": pid,
            "port": running_port,
            "message": f"MiniProxy is already running (PID {pid}).",
        }
        if dashboard or with_dashboard:
            result["dashboard"] = _ensure_dashboard(db_path, dash_port)
        return result
    if pid is not None:
        # Dead or recycled PID — clean the stale state and start fresh.
        PID_FILE.unlink(missing_ok=True)
        PORT_FILE.unlink(missing_ok=True)

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
    try:
        proc = subprocess.Popen(
            cmd, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
            env=env, start_new_session=True,
        )
    except FileNotFoundError:
        return {"status": "error",
                "message": f"'{mitmdump_path}' not found — install mitmproxy "
                           "(pip install mitmproxy) or pass --mitmdump."}
    except OSError as exc:
        return {"status": "error", "message": f"failed to launch mitmdump: {exc}"}
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
    result = {
        "status": "started",
        "pid": proc.pid,
        "port": port,
        "db": db,
        "message": f"MiniProxy started on :{port} (PID {proc.pid}, db={db}{scope_note})",
    }
    if dashboard or with_dashboard:
        result["dashboard"] = _ensure_dashboard(db, dash_port)
    return result


def _ensure_dashboard(db_path: Optional[str], dash_port: int) -> dict[str, Any]:
    """Launch the Flask dashboard as a daemon, or report the running one.

    Returns a dict with ``url`` so callers (CLI, TUI, tests) can point the
    user at a browser without guessing ports.
    """
    dash_pid = _read_dash_pid()
    if dash_pid is not None and _process_exists(dash_pid) and _pid_matches(dash_pid, "miniproxy", "dashboard"):
        port_running = _read_dash_port() or dash_port
        return {
            "status": "already_running",
            "pid": dash_pid,
            "port": port_running,
            "url": f"http://127.0.0.1:{port_running}",
            "message": f"Dashboard already running at http://127.0.0.1:{port_running}",
        }
    if dash_pid is not None:
        DASH_PID_FILE.unlink(missing_ok=True)
        DASH_PORT_FILE.unlink(missing_ok=True)

    STATE_DIR.mkdir(parents=True, exist_ok=True)
    env = os.environ.copy()
    if db_path:
        env["MINIPROXY_DB_PATH"] = str(db_path)
    cmd = [
        sys.executable, "-m", "miniproxy", "dashboard",
        "--host", "0.0.0.0", "--port", str(dash_port),
    ]
    try:
        proc = subprocess.Popen(
            cmd, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
            env=env, start_new_session=True,
        )
    except OSError as exc:
        return {"status": "error", "message": f"failed to launch dashboard: {exc}"}

    deadline = time.monotonic() + 8.0
    while time.monotonic() < deadline:
        try:
            with socket.create_connection(("127.0.0.1", dash_port), timeout=0.4):
                DASH_PID_FILE.write_text(str(proc.pid))
                DASH_PORT_FILE.write_text(str(dash_port))
                return {
                    "status": "started",
                    "pid": proc.pid,
                    "port": dash_port,
                    "url": f"http://127.0.0.1:{dash_port}",
                    "message": f"Dashboard running at http://127.0.0.1:{dash_port}",
                }
        except OSError:
            if proc.poll() is not None:
                return {
                    "status": "error",
                    "message": f"dashboard exited immediately (code {proc.returncode}) — "
                               "port already in use? Pass --dashboard-port.",
                }
            time.sleep(0.15)
    return {
        "status": "error",
        "message": f"dashboard did not bind :{dash_port} within 8s",
    }


def stop_dashboard() -> dict[str, Any]:
    """Stop the dashboard daemon (if any); the proxy is unaffected."""
    dash_pid = _read_dash_pid()
    if dash_pid is None or not _process_exists(dash_pid) or not _pid_matches(dash_pid, "miniproxy", "dashboard"):
        DASH_PID_FILE.unlink(missing_ok=True)
        DASH_PORT_FILE.unlink(missing_ok=True)
        return {"status": "not_running", "message": "Dashboard is not running."}
    try:
        os.killpg(os.getpgid(dash_pid), signal.SIGTERM)
    except (ProcessLookupError, PermissionError, OSError):
        pass
    DASH_PID_FILE.unlink(missing_ok=True)
    DASH_PORT_FILE.unlink(missing_ok=True)
    return {"status": "stopped", "message": f"Dashboard stopped (PID {dash_pid})."}


def stop() -> dict[str, Any]:
    pid = _read_pid()
    if pid is None:
        return {"status": "not_running", "message": "No PID file — nothing to stop."}
    if not _process_exists(pid) or not _pid_matches(pid, "mitmdump"):
        PID_FILE.unlink(missing_ok=True)
        PORT_FILE.unlink(missing_ok=True)
        return {
            "status": "not_running",
            "message": f"PID {pid} was stale (dead or not mitmdump) — cleaned.",
        }
    try:
        os.killpg(os.getpgid(pid), signal.SIGTERM)
    except (ProcessLookupError, PermissionError, OSError):
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
    if pid is None or not _process_exists(pid) or not _pid_matches(pid, "mitmdump"):
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
        "dashboard": _read_dash_port(),
    }

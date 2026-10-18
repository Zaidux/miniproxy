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
HOST_FILE = STATE_DIR / "mitmdump.host"
DASH_PID_FILE = STATE_DIR / "dashboard.pid"
DASH_PORT_FILE = STATE_DIR / "dashboard.port"
DASH_HOST_FILE = STATE_DIR / "dashboard.host"
DEFAULT_PORT = 8080
DEFAULT_DASH_PORT = 5000


def _dashboard_display_host(bind_host: str) -> str:
    """Return a browser-usable host for a dashboard URL.

    ``0.0.0.0`` is a bind address, not a destination address: a browser
    opened on a laptop or phone cannot route to the VPS's wildcard address.
    Prefer the VPS/LAN address when exposing the dashboard, while retaining
    loopback for the default local-only mode.
    """
    if bind_host not in ("0.0.0.0", "::", "*", ""):
        return bind_host
    try:
        from miniproxy.connect import candidate_hosts

        hosts = candidate_hosts(include_loopback=False)
        for candidate in hosts:
            host = str(candidate.get("host", "")).strip()
            if not host or host.lower().startswith(("169.254.", "fe80:", "fec0:")):
                continue
            return host
    except Exception:  # pragma: no cover - address discovery is best-effort
        pass
    return "127.0.0.1"


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


def _next_free_port(preferred: int, *, attempts: int = 20) -> Optional[int]:
    """First free port at *preferred* or above (None if all are taken).

    Scans preferred..preferred+attempts-1. Preferring the requested port
    first keeps the common case deterministic — the fallback only kicks
    in when something else already holds it.
    """
    for candidate in range(int(preferred), int(preferred) + max(int(attempts), 1)):
        if _port_free(candidate):
            return candidate
    return None


def _resolve_port(port: int | str | None) -> Optional[int]:
    """Normalize a requested port: "auto"/"0"/None → a free ephemeral port.

    Numbers (and numeric strings) pass through untouched; the busy→next-free
    fallback happens later in start(), once the requested port is known.
    """
    if port is None:
        return _next_free_port(DEFAULT_PORT)
    if isinstance(port, str):
        text = port.strip().lower()
        if text in ("auto", "0", ""):
            return _next_free_port(DEFAULT_PORT)
        try:
            return int(text)
        except ValueError:
            return None
    return int(port)


def _write_state(path: Path, text: str) -> None:
    """Write a state file, creating its directory first.

    These files live under STATE_DIR, which may not exist yet (a fresh
    MINIPROXY_STATE_DIR, a test's tmp path, or a patched constant pointing
    somewhere else). Writing them was the *last* step of a start, so a
    FileNotFoundError here left mitmdump running with no PID file — an orphan
    that `status` and `stop` could not see.
    """
    try:
        path.parent.mkdir(parents=True, exist_ok=True)
    except OSError:
        pass
    path.write_text(text)


def _wait_listening(port: int, proc: subprocess.Popen, timeout: float = 8.0) -> bool:
    """Poll until the proxy accepts connections (or the process dies)."""
    return _wait_listening_on("127.0.0.1", port, proc, timeout)


def _wait_listening_on(
    host: str, port: int, proc: subprocess.Popen, timeout: float = 8.0,
) -> bool:
    """Poll until <host>:port accepts TCP connections (or the process dies)."""
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        try:
            with socket.create_connection((host, port), timeout=0.5):
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


def _read_proxy_host(default: str = "127.0.0.1") -> str:
    """Bind address the running proxy was started with (default loopback)."""
    try:
        val = HOST_FILE.read_text().strip()
    except OSError:
        return default
    return val or default


def _allow_hosts_args(allow_clients: Optional[list[str]]) -> list[str]:
    """Build mitmdump ``--allow-hosts`` args from a client-IP allowlist.

    mitmdump refuses to start when ``allow_hosts`` is non-empty and no rule
    matches, so this both fences off an open proxy and fails loudly rather
    than silently capturing nothing.
    """
    if isinstance(allow_clients, str):
        # Tolerate a single IP passed straight through from the CLI.
        allow_clients = [allow_clients]
    hosts = [str(h).strip() for h in (allow_clients or []) if str(h).strip()]
    if not hosts:
        return []
    # One --set flag keeps every entry inside a single allow_hosts value
    # (mitmproxy takes it as a comma-separated list).
    return ["--set", "allow_hosts=" + ",".join(hosts)]


def start(
    *,
    port: int | str = DEFAULT_PORT,
    db_path: Optional[str] = None,
    scope_hosts: Optional[list[str]] = None,
    out_of_scope: str = "skip",
    mitmdump_path: str = "mitmdump",
    extra_args: Optional[list[str]] = None,
    dashboard: bool = True,
    dash_port: int | str = DEFAULT_DASH_PORT,
    dash_host: str = "127.0.0.1",
    dash_token: Optional[str] = None,
    with_dashboard: Optional[bool] = None,
    allow_clients: Optional[list[str]] = None,
    proxy_host: str = "127.0.0.1",
) -> dict[str, Any]:
    """Start the interception proxy as a background subprocess.

    Args:
        port:          Listen port (default 8080). ``"auto"`` always picks
                       a free port; if the requested port is busy the start
                       falls back to the next free port and reports it in
                       the result's ``port``/``message`` (and
                       ``fallback``=True).
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
        dash_port:     Port for the web dashboard (default 5000); same
                       busy→next-free fallback and ``"auto"`` support as
                       *port*.
        dash_host:     Bind address for the dashboard (default 127.0.0.1;
                       pass 0.0.0.0 explicitly to expose it on the LAN).
        dash_token:    Require this token on the dashboard's mutating
                       endpoints (recommended when LAN-exposed).
        allow_clients: Restricts which **destination hosts** get
                       intercepted (it becomes mitmproxy's ``allow_hosts``).
                       It is NOT a client allowlist and does not close the open
                       relay: the proxy runs with ``block_global=false`` so a
                       remote browser can use it, which means anyone who can
                       reach the port can capture through it and fill the DB.
                       Use a firewall, or keep the proxy on loopback and tunnel
                       over SSH.
        proxy_host:   Bind address for the *proxy* port. Defaults to
                       ``127.0.0.1`` so the proxy is NOT published to the
                       internet by default — reach it from another machine over
                       an SSH tunnel (``ssh -L <port>:127.0.0.1:<port> …``).
                       Pass ``0.0.0.0`` to serve the LAN/public, and pair it
                       with a firewall (not *allow_clients*, which does not
                       restrict clients).
    """
    # `dashboard` defaults to True, so `dashboard or with_dashboard` was always
    # true and with_dashboard=False could never suppress it. The explicit flag
    # wins when given: the header's Start button passes False meaning "proxy
    # only", and used to spawn a second dashboard instead.
    want_dashboard = dashboard if with_dashboard is None else bool(with_dashboard)
    pid = _read_pid()
    if pid is not None and _process_exists(pid) and _pid_matches(pid, "mitmdump"):
        running_port = _read_port()
        result = {
            "status": "already_running",
            "pid": pid,
            "port": running_port,
            "message": f"MiniProxy is already running (PID {pid}).",
        }
        if want_dashboard:
            # "auto" must not clobber a dashboard that is already up: the
            # ensure path below reports it with its recorded port.
            requested_dash = dash_port
            result["dashboard"] = _ensure_dashboard(
                db_path, _resolve_port(requested_dash) or DEFAULT_DASH_PORT,
                dash_host, dash_token,
            )
        return result
    if pid is not None:
        # Dead or recycled PID — clean the stale state and start fresh.
        PID_FILE.unlink(missing_ok=True)
        PORT_FILE.unlink(missing_ok=True)
        HOST_FILE.unlink(missing_ok=True)

    script = addon_path()
    if not script.exists():
        return {"status": "error",
                "message": f"Addon not found at {script} (broken install?)."}

    port = _resolve_port(port)
    if port is None:
        return {"status": "error",
                "message": "--port auto: no free port found (tried 20 candidates)."}
    port = int(port)
    fallback_port = False
    if not _port_free(port):
        moved = _next_free_port(port)
        if moved is None:
            return {"status": "error",
                    "message": f"Port {port} is already in use and no free "
                               f"port was found in {port}..{port + 19}."}
        fallback_port = True
        port = moved

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
         "--listen-host", proxy_host, "--listen-port", str(port)]
        + _allow_hosts_args(allow_clients)
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
    # mitmdump binds only the address it was given, so probing 127.0.0.1 for a
    # non-loopback --proxy-host always failed; the child then stayed alive with
    # no PID file written. Loopback keeps using _wait_listening, which is the
    # seam the tests patch.
    probe_host = proxy_host
    if proxy_host in ("0.0.0.0", "::", "", "127.0.0.1", "localhost"):
        ready = _wait_listening(port, proc)
        probe_host = "127.0.0.1"
    else:
        ready = _wait_listening_on(proxy_host, port, proc)
    if not ready:
        try:
            proc.terminate()
            proc.wait(timeout=3)
        except Exception:
            try:
                proc.kill()
            except Exception:
                pass
        return {"status": "error",
                "message": f"mitmdump did not bind {probe_host}:{port} within 8s "
                           f"(PID {proc.pid}); the process was stopped."}

    _write_state(PID_FILE, str(proc.pid))
    _write_state(PORT_FILE, str(port))
    _write_state(HOST_FILE, proxy_host)
    scope_note = (
        f", scope={len(hosts)} host(s) (out-of-scope: "
        f"{env.get('MINIPROXY_SCOPE_MODE', 'skip')})" if hosts else ""
    )
    result = {
        "status": "started",
        "pid": proc.pid,
        "port": port,
        "db": db,
        "fallback": fallback_port,
        "message": f"MiniProxy started on :{port} (PID {proc.pid}, db={db}{scope_note})",
    }
    if fallback_port:
        result["message"] = (
            f"MiniProxy started on :{port} — requested port was busy, "
            f"moved up (PID {proc.pid}, db={db}{scope_note})"
        )
    if want_dashboard:
        result["dashboard"] = _ensure_dashboard(db, dash_port, dash_host, dash_token)
    return result


def _ensure_dashboard(
    db_path: Optional[str],
    dash_port: int | str,
    dash_host: str = "127.0.0.1",
    dash_token: Optional[str] = None,
) -> dict[str, Any]:
    """Launch the Flask dashboard as a daemon, or report the running one.

    Returns a dict with ``url`` so callers (CLI, TUI, tests) can point the
    user at a browser without guessing ports. The bind address defaults to
    loopback; LAN exposure is an explicit caller choice (and should come
    with a token). *dash_port* accepts "auto" and falls back to the next
    free port when the requested one is busy (the result's ``port`` and
    ``url`` reflect what actually bound).
    """
    dash_pid = _read_dash_pid()
    if dash_pid is not None and _process_exists(dash_pid) and _pid_matches(dash_pid, "miniproxy", "dashboard"):
        port_running = _read_dash_port() or dash_port
        # Prefer the bind address recorded at launch. Otherwise a later
        # `miniproxy start` with the default loopback option would make an
        # already-public dashboard appear to be local-only.
        try:
            recorded_host = DASH_HOST_FILE.read_text().strip()
        except OSError:
            recorded_host = ""
        display_host = _dashboard_display_host(recorded_host or dash_host)
        return {
            "status": "already_running",
            "pid": dash_pid,
            "port": port_running,
            "url": f"http://{display_host}:{port_running}",
            "message": f"Dashboard already running at http://{display_host}:{port_running}",
        }
    if dash_pid is not None:
        DASH_PID_FILE.unlink(missing_ok=True)
        DASH_PORT_FILE.unlink(missing_ok=True)
        DASH_HOST_FILE.unlink(missing_ok=True)

    resolved = _resolve_port(dash_port)
    if resolved is None:
        return {"status": "error", "message": "--dashboard-port auto: no free port found."}
    dash_port = resolved
    fallback_dash = False
    if not _port_free(dash_port):
        moved = _next_free_port(dash_port)
        if moved is None:
            return {"status": "error",
                    "message": f"Dashboard port {dash_port} is already in use and "
                               f"no free port was found in {dash_port}..{dash_port + 19}."}
        fallback_dash = True
        dash_port = moved

    STATE_DIR.mkdir(parents=True, exist_ok=True)
    env = os.environ.copy()
    if db_path:
        env["MINIPROXY_DB_PATH"] = str(db_path)
    if dash_token:
        env["MINIPROXY_DASHBOARD_TOKEN"] = dash_token
    cmd = [
        sys.executable, "-m", "miniproxy", "dashboard",
        "--host", dash_host, "--port", str(dash_port),
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
                _write_state(DASH_PID_FILE, str(proc.pid))
                _write_state(DASH_PORT_FILE, str(dash_port))
                _write_state(DASH_HOST_FILE, dash_host)
                display_host = _dashboard_display_host(dash_host)
                return {
                    "status": "started",
                    "pid": proc.pid,
                    "port": dash_port,
                    "fallback": fallback_dash,
                    "url": f"http://{display_host}:{dash_port}",
                    "message": (
                        f"Dashboard running at http://{display_host}:{dash_port}"
                        if not fallback_dash else
                        f"Dashboard running at http://{display_host}:{dash_port} "
                        "— requested port was busy, moved up"
                    ),
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
        DASH_HOST_FILE.unlink(missing_ok=True)
        return {"status": "not_running", "message": "Dashboard is not running."}
    try:
        os.killpg(os.getpgid(dash_pid), signal.SIGTERM)
    except (ProcessLookupError, PermissionError, OSError):
        pass
    DASH_PID_FILE.unlink(missing_ok=True)
    DASH_PORT_FILE.unlink(missing_ok=True)
    DASH_HOST_FILE.unlink(missing_ok=True)
    return {"status": "stopped", "message": f"Dashboard stopped (PID {dash_pid})."}


def stop() -> dict[str, Any]:
    pid = _read_pid()
    if pid is None:
        return {"status": "not_running", "message": "No PID file — nothing to stop."}
    if not _process_exists(pid) or not _pid_matches(pid, "mitmdump"):
        PID_FILE.unlink(missing_ok=True)
        PORT_FILE.unlink(missing_ok=True)
        HOST_FILE.unlink(missing_ok=True)
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
    HOST_FILE.unlink(missing_ok=True)
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
            HOST_FILE.unlink(missing_ok=True)
        return {"status": "not_running", "pid": None, "port": None,
                "host": None, "message": "MiniProxy is not running."}
    return {
        "status": "running",
        "pid": pid,
        "port": _read_port(),
        # Loopback unless it was explicitly published — the connect wizard
        # uses this to know whether devices can reach the port directly.
        "host": _read_proxy_host(),
        "db": os.environ.get("MINIPROXY_DB_PATH") or str(STATE_DIR / "proxy.db"),
        "message": f"MiniProxy is running (PID {pid}).",
        "dashboard": _read_dash_port(),
    }

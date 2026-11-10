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
import socket
import subprocess
import sys
import time
import tempfile
import uuid
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
# Recovery ownership when a filesystem error interrupts provisional publication.
# Never substitute these anchors for a different PID read from disk.
_PENDING_PROCESSES: dict[Path, tuple[int, str]] = {}


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
        pending = _PENDING_PROCESSES.get(PID_FILE)
        return pending[0] if pending else None


def _process_exists(pid: int) -> bool:
    try:
        os.kill(pid, 0)
        return True
    except OSError:
        return False


def validate_port(port: int | str | None, *, allow_auto: bool = True) -> int | str:
    """One validation contract for CLI and programmatic bind addresses."""
    if isinstance(port, bool):
        raise ValueError("Port must be an integer in 1..65535 or 'auto'")
    if allow_auto and (port is None or port == "" or str(port).strip().lower() in ("auto", "0")):
        return "auto"
    if not isinstance(port, (int, str)):
        raise ValueError("Port must be an integer in 1..65535 or 'auto'")
    try:
        value = int(port)
    except (ValueError, TypeError):
        raise ValueError("Port must be an integer in 1..65535 or 'auto'") from None
    if not 1 <= value <= 65535:
        raise ValueError("Port must be in 1..65535 (0/'auto' selects a free port)")
    return value


def _port_free(port: int, host: str = "0.0.0.0") -> bool:
    if not isinstance(port, int) or not 1 <= port <= 65535:
        return False
    family = socket.AF_INET6 if ":" in host else socket.AF_INET
    with socket.socket(family, socket.SOCK_STREAM) as s:
        s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        try:
            s.bind((host, port))
            return True
        except OSError:
            return False


def _next_free_port(preferred: int, *, attempts: int = 20, host: str = "0.0.0.0") -> Optional[int]:
    """First free port at *preferred* or above (None if all are taken).

    Scans preferred..preferred+attempts-1. Preferring the requested port
    first keeps the common case deterministic — the fallback only kicks
    in when something else already holds it.
    """
    for candidate in range(max(1, int(preferred)), min(int(preferred) + max(int(attempts), 1), 65536)):
        if (_port_free(candidate) if host == "0.0.0.0" else _port_free(candidate, host)):
            return candidate
    return None


def _resolve_port(port: int | str | None, *, host: str = "0.0.0.0") -> Optional[int]:
    """Normalize a requested port: "auto"/"0"/None → a free ephemeral port.

    Numbers (and numeric strings) pass through untouched; the busy→next-free
    fallback happens later in start(), once the requested port is known.
    """
    try:
        value = validate_port(port)
    except ValueError:
        return None
    if value == "auto":
        return _next_free_port(DEFAULT_PORT) if host == "0.0.0.0" else _next_free_port(DEFAULT_PORT, host=host)
    return value


def _bind_port_free(port: int, host: str) -> bool:
    # Preserve the established single-argument patch seam for IPv4 fixtures.
    return _port_free(port, host) if ":" in host else _port_free(port)


def _bind_next_free_port(port: int, host: str) -> int | None:
    return _next_free_port(port, host=host) if ":" in host else _next_free_port(port)


def _write_state(path: Path, text: str) -> None:
    """Write a state file, creating its directory first.

    These files live under STATE_DIR, which may not exist yet (a fresh
    MINIPROXY_STATE_DIR, a test's tmp path, or a patched constant pointing
    somewhere else). Writing them was the *last* step of a start, so a
    FileNotFoundError here left mitmdump running with no PID file — an orphan
    that `status` and `stop` could not see.
    """
    path.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
    fd, temporary = tempfile.mkstemp(prefix=".state-", dir=path.parent)
    try:
        with os.fdopen(fd, "w", encoding="utf-8") as stream:
            stream.write(text)
            stream.flush()
            os.fsync(stream.fileno())
        os.replace(temporary, path)
    finally:
        Path(temporary).unlink(missing_ok=True)


def _manifest_path(pid_path: Path) -> Path:
    return pid_path.with_suffix(".session.json")


def _read_manifest(pid_path: Path, pid: int | None = None) -> dict[str, Any]:
    """Never attribute a previous run's metadata to a recycled process."""
    try:
        data = json.loads(_manifest_path(pid_path).read_text())
        identity = pid_path.with_suffix(".identity").read_text().strip()
        if (isinstance(data, dict) and data.get("schema_version") == 1 and
                data.get("pid") == pid and identity and data.get("process_identity") == identity):
            return data
    except (OSError, ValueError):
        pass
    return {}


def _publish_manifest(proc, pid_path: Path, port_path: Path, host_path: Path,
                      metadata: dict[str, Any]) -> bool:
    from miniproxy.runtime import process_identity
    from miniproxy import __version__
    try:
        document = {"schema_version": 1, "package_version": __version__,
                    "session_id": uuid.uuid4().hex, "started_at": time.time(),
                    "pid": proc.pid, "process_identity": process_identity(proc.pid), **metadata}
        from miniproxy.automation import addon_manifest
        if pid_path == PID_FILE:
            document["addon_manifest"] = addon_manifest()
        _write_state(_manifest_path(pid_path), json.dumps(document, sort_keys=True))
        return True
    except Exception:
        if _stop_owned_group(pid_path, proc.pid):
            proc.wait(timeout=3)
            _clear_process_state(pid_path, port_path, host_path)
        return False


def capture_db_path(explicit: str | None = None) -> str:
    """CLI readers follow the launched DB unless the caller explicitly overrides it."""
    if explicit or os.environ.get("MINIPROXY_DB_PATH"):
        return str(Path(explicit or os.environ["MINIPROXY_DB_PATH"]).expanduser().resolve())
    pid = _read_pid()
    manifest = _read_manifest(PID_FILE, pid) if pid is not None and _owned_process(PID_FILE, pid) else {}
    return manifest.get("db") or str(STATE_DIR / "proxy.db")


def _probe_host(bind_host: str) -> str:
    if bind_host == "::":
        return "::1"
    return "127.0.0.1" if bind_host in ("0.0.0.0", "", "*", "localhost") else bind_host


def _http_url(host: str, port: int) -> str:
    return f"http://{'[' + host + ']' if ':' in host else host}:{port}"


def _effective_ca_path(extra_args: list[str] | None) -> str:
    from miniproxy.connect import ca_cert_path
    selected = str(ca_cert_path())
    for argument in _set_arguments(extra_args):
        if argument.startswith("confdir="):
            selected = str(Path(argument.split("=", 1)[1]).expanduser().resolve() / "mitmproxy-ca-cert.pem")
    return selected


def _set_arguments(extra_args: list[str] | None) -> list[str]:
    result = []
    take_next = False
    for argument in extra_args or []:
        if take_next:
            result.append(argument)
            take_next = False
        elif argument == "--set":
            take_next = True
        elif argument.startswith("--set="):
            result.append(argument[len("--set="):])
    return result


def _preflight_policy(out_of_scope: str) -> None:
    """Validate the same effective policy the child will load, before spawning."""
    from miniproxy.scope import load_policy, network_scope
    # Canonical RULES/exclusions must be valid independently of capture scope.
    for name in ("MINIPROXY_RULES_SCOPE", "MINIPROXY_EXCLUDE_SCOPE"):
        entries = load_policy(name)
        if entries is not None and any(network_scope(entry, allow_wildcard=True) is None for entry in entries):
            raise ValueError(f"Invalid canonical policy in {name}")
    if out_of_scope not in ("skip", "block"):
        raise ValueError("out_of_scope must be 'skip' or 'block'")


def _inherited_scope(entries: list[str] | None) -> list[str] | None:
    if entries is not None or not os.environ.get("MINIPROXY_SCOPE"):
        return entries
    from miniproxy.scope import load_scope
    return load_scope()[0]


def _write_process_identity(path: Path, pid: int) -> None:
    from miniproxy.runtime import process_identity
    _write_state(path.with_suffix(".identity"), process_identity(pid))


def _owned_process(path: Path, pid: int) -> bool:
    from miniproxy.runtime import process_identity
    try:
        identity = path.with_suffix(".identity").read_text().strip()
    except OSError:
        pending = _PENDING_PROCESSES.get(path)
        identity = pending[1] if pending and pending[0] == pid else ""
    return bool(identity) and process_identity(pid) == identity


def _stop_owned_group(path: Path, pid: int) -> bool:
    from miniproxy.runtime import terminate_process_group
    try:
        identity = path.with_suffix(".identity").read_text().strip()
    except OSError:
        pending = _PENDING_PROCESSES.get(path)
        identity = pending[1] if pending and pending[0] == pid else ""
    return terminate_process_group(pid, identity)


def _clear_process_state(pid_path: Path, port_path: Path, host_path: Path) -> None:
    for path in (pid_path, pid_path.with_suffix(".identity"), port_path, host_path, _manifest_path(pid_path)):
        path.unlink(missing_ok=True)
    _PENDING_PROCESSES.pop(pid_path, None)


def _publish_process_state(proc, pid_path: Path, port_path: Path,
                           host_path: Path, port: int, host: str) -> bool:
    """Publish provisional ownership, or retire the exact child on failure.

    Cleanup uses the creation identity captured from Popen, not partially
    written disk state. If cleanup is ambiguous, keep/retry the recovery anchor
    rather than advertise success or delete the only way to find the child.
    """
    from miniproxy.runtime import process_identity, terminate_process_group
    identity = process_identity(proc.pid)
    _PENDING_PROCESSES[pid_path] = (proc.pid, identity)
    try:
        if not identity:
            raise RuntimeError("Spawned process identity is unavailable")
        _write_state(pid_path, str(proc.pid))
        _write_state(pid_path.with_suffix(".identity"), identity)
        _write_state(port_path, str(port))
        _write_state(host_path, host)
    except Exception:
        if terminate_process_group(proc.pid, identity):
            proc.wait(timeout=3)
            _clear_process_state(pid_path, port_path, host_path)
        else:
            for path, value in ((pid_path, str(proc.pid)),
                                (pid_path.with_suffix(".identity"), identity)):
                try:
                    _write_state(path, value)
                except OSError:
                    pass  # the in-memory anchor still allows same-process stop
        return False
    return True


def _wait_listening(port: int, proc: subprocess.Popen, timeout: float = 30.0) -> bool:
    """Poll until the proxy accepts connections (or the process dies)."""
    return _wait_listening_on("127.0.0.1", port, proc, timeout)


def _wait_listening_on(
    host: str, port: int, proc: subprocess.Popen, timeout: float = 30.0,
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
        pending = _PENDING_PROCESSES.get(DASH_PID_FILE)
        return pending[0] if pending else None


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
    """Destination-interception filters, never a client-IP access boundary."""
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
    try:
        validate_port(port)
        if want_dashboard:
            validate_port(dash_port)
    except ValueError as exc:
        return {"status": "error", "error_type": "invalid_port", "message": str(exc)}
    inherited_mode = os.environ.get("MINIPROXY_SCOPE_MODE", "skip").strip().lower() if scope_hosts is None else "skip"
    if inherited_mode not in {"skip", "block"}:
        return {"status": "error", "error_type": "invalid_scope", "message": "Invalid inherited scope mode"}
    scope_hosts = _inherited_scope(scope_hosts)
    if out_of_scope == "skip" and inherited_mode == "block":
        out_of_scope = "block"
    from miniproxy.scope import network_scope
    if scope_hosts is not None and (not isinstance(scope_hosts, list) or not scope_hosts or
            any(not isinstance(h, str) or network_scope(h, allow_wildcard=True) is None for h in scope_hosts)):
        return {"status": "error", "error_type": "invalid_scope", "message": "Scope must be a nonempty list of canonical host/HTTP URL entries"}
    from miniproxy.scope import load_policy, scope_contains
    allowed_roots = load_policy("MINIPROXY_RULES_SCOPE")
    if scope_hosts and allowed_roots is not None and any(
            not any(scope_contains(entry, root) for root in allowed_roots) for entry in scope_hosts):
        return {"status": "error", "error_type": "invalid_scope", "message": "Requested capture scope exceeds canonical RULES scope"}
    try:
        _preflight_policy(out_of_scope)
    except ValueError as exc:
        return {"status": "error", "error_type": "invalid_scope", "message": str(exc)}
    # Child option overrides must not defeat listener/DB/scope ownership metadata.
    if extra_args is not None and (not isinstance(extra_args, list) or
            not all(isinstance(arg, str) for arg in extra_args)):
        return {"status": "error", "error_type": "invalid_proxy_option", "message": "extra_args must be a list of strings"}
    forbidden_options = {"--listen-host", "--listen-port", "-p", "--mode", "-m", "--scripts", "-s"}
    policy_settings = {"listen_host", "listen_port", "mode", "scripts"}
    if any(argument.split("=", 1)[0] in policy_settings for argument in _set_arguments(extra_args)):
        return {"status": "error", "error_type": "conflicting_proxy_option", "message": "Extra proxy settings cannot override owned listener/mode/addon options"}
    for argument in extra_args or []:
        option = argument.split("=", 1)[0]
        abbreviated_owned = argument.startswith("--") and any(
            owned.startswith(option) for owned in forbidden_options if owned.startswith("--"))
        if (option in forbidden_options or
                (argument.startswith(("-p", "-m", "-s")) and not argument.startswith("--")) or
                abbreviated_owned or
                ("=" in argument and argument.split("=", 1)[0] in policy_settings)):
            return {"status": "error", "error_type": "conflicting_proxy_option",
                    "message": "Extra proxy arguments cannot override owned listener/mode/addon options"}
    from miniproxy.runtime import resolve_mitmdump
    try:
        mitmdump_path = resolve_mitmdump(mitmdump_path)
    except RuntimeError as exc:
        return {"status": "error", "message": str(exc)}
    pid = _read_pid()
    if pid is not None and _process_exists(pid):
        if not _owned_process(PID_FILE, pid):
            return {"status": "error", "pid": pid, "message": "Proxy ownership is unverified; existing state retained."}
        running_port = _read_port()
        result = {
            "status": "already_running",
            "pid": pid,
            "port": running_port,
            "message": f"MiniProxy is already running (PID {pid}).",
        }
        manifest = _read_manifest(PID_FILE, pid)
        result.update({key: manifest[key] for key in ("db", "session_id", "scope", "scope_mode") if key in manifest})
        if want_dashboard:
            # "auto" must not clobber a dashboard that is already up: the
            # ensure path below reports it with its recorded port.
            requested_dash = dash_port
            result["dashboard"] = _ensure_dashboard(
                manifest.get("db") or db_path, _resolve_port(requested_dash) or DEFAULT_DASH_PORT,
                dash_host, dash_token,
            )
        return result
    if pid is not None:
        # Dead or recycled PID — clean the stale state and start fresh.
        from miniproxy.runtime import process_group_exited
        if not process_group_exited(pid):
            return {"status": "error", "pid": pid, "message": "Proxy leader exited but group termination is unconfirmed; state retained."}
        _clear_process_state(PID_FILE, PORT_FILE, HOST_FILE)

    script = addon_path()
    if not script.exists():
        return {"status": "error",
                "message": f"Addon not found at {script} (broken install?)."}

    port = _resolve_port(port, host=proxy_host) if ":" in proxy_host else _resolve_port(port)
    if port is None:
        return {"status": "error",
                "message": "--port auto: no free port found (tried 20 candidates)."}
    port = int(port)
    fallback_port = False
    if not _bind_port_free(port, proxy_host):
        moved = _bind_next_free_port(port, proxy_host)
        if moved is None:
            return {"status": "error",
                    "message": f"Port {port} is already in use and no free "
                               f"port was found in {port}..{port + 19}."}
        fallback_port = True
        port = moved

    STATE_DIR.mkdir(parents=True, exist_ok=True)
    db = str(Path(db_path or os.environ.get("MINIPROXY_DB_PATH")
             or (STATE_DIR / "proxy.db")).expanduser().resolve())

    env = os.environ.copy()
    env["MINIPROXY_DB_PATH"] = db
    hosts = [h.strip() for h in (scope_hosts or [])]
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
                "message": f"'{mitmdump_path}' not found — install mitmproxy's maintained distribution "
                           "(python -m pip install riciplay-mitmproxy==12.3.1.1) in the active environment."}
    except OSError as exc:
        return {"status": "error", "message": f"failed to launch mitmdump: {exc}"}
    # Provisional ownership remains available even when readiness fails.
    if not _publish_process_state(proc, PID_FILE, PORT_FILE, HOST_FILE, port, proxy_host):
        return {"status": "error", "pid": proc.pid, "message": "Proxy ownership publication failed; startup aborted. " +
                ("Cleanup unconfirmed; recovery ownership retained." if PID_FILE in _PENDING_PROCESSES else "Process group stopped.")}
    if not _publish_manifest(proc, PID_FILE, PORT_FILE, HOST_FILE,
            {"db": db, "host": proxy_host, "port": port, "scope": hosts,
             "scope_mode": env.get("MINIPROXY_SCOPE_MODE", "skip"),
             "ca_certificate_path": _effective_ca_path(extra_args),
             "excluded_scope": env.get("MINIPROXY_EXCLUDE_SCOPE"),
             "rules_scope": env.get("MINIPROXY_RULES_SCOPE")}):
        retained = PID_FILE.exists() or PID_FILE in _PENDING_PROCESSES
        return {"status": "error", "pid": proc.pid,
                "message": "Proxy session metadata publication failed; startup aborted. " +
                           ("Cleanup unconfirmed; ownership retained." if retained else "Process group stopped.")}
    time.sleep(0.5)
    if proc.poll() is not None:
        if _stop_owned_group(PID_FILE, proc.pid):
            _clear_process_state(PID_FILE, PORT_FILE, HOST_FILE)
        return {"status": "error",
                "message": f"mitmdump exited immediately (code {proc.returncode}). "
                           "Is mitmproxy installed?"}
    # mitmdump binds only the address it was given, so probing 127.0.0.1 for a
    # non-loopback --proxy-host always failed; the child then stayed alive with
    # no PID file written. Loopback keeps using _wait_listening, which is the
    # seam the tests patch.
    probe_host = proxy_host
    if proxy_host in ("0.0.0.0", "", "127.0.0.1", "localhost"):
        ready = _wait_listening(port, proc)
        probe_host = "127.0.0.1"
    else:
        probe_host = _probe_host(proxy_host)
        ready = _wait_listening_on(probe_host, port, proc)
    if not ready:
        cleaned = _stop_owned_group(PID_FILE, proc.pid)
        if cleaned:
            proc.wait(timeout=3)
            _clear_process_state(PID_FILE, PORT_FILE, HOST_FILE)
        return {"status": "error",
                "message": f"mitmdump did not bind {probe_host}:{port} within 30s "
                           f"(PID {proc.pid}); " + ("the process was stopped." if cleaned else
                           "cleanup unconfirmed; ownership state retained.")}

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
    result["session_id"] = _read_manifest(PID_FILE, proc.pid).get("session_id")
    result["scope"] = hosts
    result["scope_mode"] = env.get("MINIPROXY_SCOPE_MODE", "skip")
    result["host"] = proxy_host
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
    try:
        validate_port(dash_port)
    except ValueError as exc:
        return {"status": "error", "error_type": "invalid_port", "message": str(exc)}
    dash_pid = _read_dash_pid()
    if dash_pid is not None and _process_exists(dash_pid):
        if not _owned_process(DASH_PID_FILE, dash_pid):
            return {"status": "error", "pid": dash_pid, "message": "Dashboard ownership is unverified; existing state retained."}
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
            "url": _http_url(display_host, int(port_running)),
            "message": f"Dashboard already running at http://{display_host}:{port_running}",
        }
    if dash_pid is not None:
        from miniproxy.runtime import process_group_exited
        if not process_group_exited(dash_pid):
            return {"status": "error", "pid": dash_pid, "message": "Dashboard leader exited but group termination is unconfirmed; state retained."}
        _clear_process_state(DASH_PID_FILE, DASH_PORT_FILE, DASH_HOST_FILE)

    resolved = _resolve_port(dash_port, host=dash_host) if ":" in dash_host else _resolve_port(dash_port)
    if resolved is None:
        return {"status": "error", "message": "--dashboard-port auto: no free port found."}
    dash_port = resolved
    fallback_dash = False
    if not _bind_port_free(dash_port, dash_host):
        moved = _bind_next_free_port(dash_port, dash_host)
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

    if not _publish_process_state(proc, DASH_PID_FILE, DASH_PORT_FILE, DASH_HOST_FILE, dash_port, dash_host):
        return {"status": "error", "pid": proc.pid, "message": "Dashboard ownership publication failed; startup aborted. " +
                ("Cleanup unconfirmed; recovery ownership retained." if DASH_PID_FILE in _PENDING_PROCESSES else "Process group stopped.")}
    if not _publish_manifest(proc, DASH_PID_FILE, DASH_PORT_FILE, DASH_HOST_FILE,
            {"db": str(Path(db_path or env.get("MINIPROXY_DB_PATH") or STATE_DIR / "proxy.db").expanduser().resolve()),
             "host": dash_host, "port": dash_port, "auth_enabled": bool(dash_token or env.get("MINIPROXY_DASHBOARD_TOKEN"))}):
        retained = DASH_PID_FILE.exists() or DASH_PID_FILE in _PENDING_PROCESSES
        return {"status": "error", "pid": proc.pid,
                "message": "Dashboard session metadata publication failed; startup aborted. " +
                           ("Cleanup unconfirmed; ownership retained." if retained else "Process group stopped.")}

    deadline = time.monotonic() + 8.0
    while time.monotonic() < deadline:
        try:
            with socket.create_connection((_probe_host(dash_host), dash_port), timeout=0.4):
                display_host = _dashboard_display_host(dash_host)
                return {
                    "status": "started",
                    "pid": proc.pid,
                    "port": dash_port,
                    "fallback": fallback_dash,
                    "url": _http_url(display_host, dash_port),
                    "message": (
                        f"Dashboard running at http://{display_host}:{dash_port}"
                        if not fallback_dash else
                        f"Dashboard running at http://{display_host}:{dash_port} "
                        "— requested port was busy, moved up"
                    ),
                }
        except OSError:
            if proc.poll() is not None:
                if _stop_owned_group(DASH_PID_FILE, proc.pid):
                    _clear_process_state(DASH_PID_FILE, DASH_PORT_FILE, DASH_HOST_FILE)
                return {
                    "status": "error",
                    "message": f"dashboard exited immediately (code {proc.returncode}) — "
                               "port already in use? Pass --dashboard-port.",
                }
            time.sleep(0.15)
    cleaned = _stop_owned_group(DASH_PID_FILE, proc.pid)
    if cleaned:
        proc.wait(timeout=3)
        _clear_process_state(DASH_PID_FILE, DASH_PORT_FILE, DASH_HOST_FILE)
    return {
        "status": "error",
        "message": f"dashboard did not bind :{dash_port} within 8s; " +
                   ("process stopped." if cleaned else "cleanup unconfirmed; ownership state retained."),
    }


def stop_dashboard() -> dict[str, Any]:
    """Stop the dashboard daemon (if any); the proxy is unaffected."""
    dash_pid = _read_dash_pid()
    if dash_pid is None or not _process_exists(dash_pid):
        from miniproxy.runtime import process_group_exited
        if dash_pid is not None and not process_group_exited(dash_pid):
            return {"status": "error", "message": "Dashboard group termination unconfirmed; ownership state retained."}
        _clear_process_state(DASH_PID_FILE, DASH_PORT_FILE, DASH_HOST_FILE)
        return {"status": "not_running", "message": "Dashboard is not running."}
    if not _owned_process(DASH_PID_FILE, dash_pid):
        return {"status": "error", "message": "Dashboard process ownership is unverified; no process was signalled."}
    if not _stop_owned_group(DASH_PID_FILE, dash_pid):
        return {"status": "error", "message": "Dashboard termination unconfirmed; ownership state retained."}
    _clear_process_state(DASH_PID_FILE, DASH_PORT_FILE, DASH_HOST_FILE)
    return {"status": "stopped", "message": f"Dashboard stopped (PID {dash_pid})."}


def stop() -> dict[str, Any]:
    pid = _read_pid()
    if pid is None:
        return {"status": "not_running", "message": "No PID file — nothing to stop."}
    if not _process_exists(pid):
        from miniproxy.runtime import process_group_exited
        if not process_group_exited(pid):
            return {"status": "error", "message": "Proxy group termination unconfirmed; ownership state retained."}
        _clear_process_state(PID_FILE, PORT_FILE, HOST_FILE)
        return {
            "status": "not_running",
            "message": f"PID {pid} was stale (dead or not mitmdump) — cleaned.",
        }
    if not _owned_process(PID_FILE, pid):
        return {"status": "error", "message": "Proxy process ownership is unverified; no process was signalled."}
    if not _stop_owned_group(PID_FILE, pid):
        return {"status": "error", "message": "Proxy termination unconfirmed; ownership state retained."}
    _clear_process_state(PID_FILE, PORT_FILE, HOST_FILE)
    return {"status": "stopped", "message": f"MiniProxy terminated (PID {pid})."}


def _read_port() -> Optional[int]:
    try:
        return int(PORT_FILE.read_text().strip())
    except (OSError, ValueError):
        return None


def status() -> dict[str, Any]:
    pid = _read_pid()
    if pid is None or not _process_exists(pid):
        from miniproxy.runtime import process_group_exited
        if pid is not None and not process_group_exited(pid):
            return {"status": "error", "pid": pid, "message": "Proxy group termination unconfirmed; ownership state retained."}
        if pid is not None:
            _clear_process_state(PID_FILE, PORT_FILE, HOST_FILE)
        return {"status": "not_running", "pid": None, "port": None,
                "host": None, "message": "MiniProxy is not running."}
    if not _owned_process(PID_FILE, pid):
        return {"status": "error", "pid": pid, "port": _read_port(), "host": _read_proxy_host(),
                "message": "Proxy ownership is unverified; existing state retained."}
    manifest = _read_manifest(PID_FILE, pid)
    port = manifest.get("port", _read_port())
    host = manifest.get("host", _read_proxy_host())
    mismatch = bool(manifest) and ((_read_port() is not None and _read_port() != port) or _read_proxy_host() != host)
    return {
        "status": "error" if mismatch else "running",
        "pid": pid,
        "port": port,
        # Loopback unless it was explicitly published — the connect wizard
        # uses this to know whether devices can reach the port directly.
        "host": host,
        "db": manifest.get("db"),
        "session_id": manifest.get("session_id"),
        "metadata_verified": bool(manifest),
        "scope": manifest.get("scope"),
        "scope_mode": manifest.get("scope_mode"),
        "ca_certificate_path": manifest.get("ca_certificate_path"),
        "addon_manifest": manifest.get("addon_manifest"),
        "state_integrity_error": mismatch,
        "message": "Session manifest contradicts listener sidecars; ownership retained." if mismatch else f"MiniProxy is running (PID {pid}).",
        "dashboard": _read_dash_port(),
    }


def health() -> dict[str, Any]:
    """Bounded local readiness, without sending a third-party CONNECT probe."""
    from miniproxy import __version__
    from miniproxy.connect import ca_cert_path
    from miniproxy.runtime import environment_error
    state = status()
    process_alive = state.get("status") == "running"
    listener_ready = False
    port = state.get("port")
    if process_alive and isinstance(port, int) and 1 <= port <= 65535:
        try:
            with socket.create_connection((_probe_host(state.get("host") or "127.0.0.1"), port), timeout=0.5):
                listener_ready = True
        except OSError:
            pass
    capture_ready = False
    db_path = state.get("db")
    if process_alive and db_path:
        import sqlite3
        try:
            with sqlite3.connect(Path(db_path).as_uri() + "?mode=ro", uri=True, timeout=0.5) as connection:
                connection.execute("SELECT id FROM requests LIMIT 1").fetchall()
                capture_ready = True
        except (OSError, ValueError, sqlite3.Error):
            pass
    error = environment_error()
    ready = process_alive and listener_ready and capture_ready and not error
    dash_pid = _read_dash_pid()
    dashboard = {"process_alive": False, "listener_ready": False, "metadata_verified": False}
    if dash_pid is not None and _process_exists(dash_pid) and _owned_process(DASH_PID_FILE, dash_pid):
        dash_metadata = _read_manifest(DASH_PID_FILE, dash_pid)
        dashboard.update(process_alive=True, metadata_verified=bool(dash_metadata),
                         port=_read_dash_port(), host=dash_metadata.get("host"),
                         auth_enabled=dash_metadata.get("auth_enabled"))
        if dash_metadata.get("host") and isinstance(dashboard["port"], int):
            try:
                with socket.create_connection((_probe_host(dash_metadata["host"]), dashboard["port"]), timeout=0.5):
                    dashboard["listener_ready"] = True
            except OSError:
                pass
    return {**state, "schema_version": 1, "package_version": __version__,
            "status": "ready" if ready else "not_ready", "process_alive": process_alive,
            "listener_ready": listener_ready, "capture_ready": capture_ready,
            "forwarding_verified": False, "dependency_error": error,
            "ca_certificate_path": state.get("ca_certificate_path") or str(ca_cert_path()), "dashboard_health": dashboard, "ready": ready}

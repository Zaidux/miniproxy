"""Local-only proxy distribution/version gate shared by CLI and launcher."""
from __future__ import annotations

from importlib import metadata
from importlib.util import find_spec
from pathlib import Path
import os
import shutil
import sys
import sysconfig
import subprocess
import signal
import time

from packaging.specifiers import SpecifierSet
from packaging.version import InvalidVersion


def runtime_info():
    from miniproxy import __version__

    def installed(name):
        try:
            return metadata.version(name)
        except metadata.PackageNotFoundError:
            return None

    def supported(value, spec):
        try:
            return value is not None and SpecifierSet(spec).contains(value, prereleases=False)
        except InvalidVersion:
            return False

    fork = installed("riciplay-mitmproxy")
    upstream = installed("mitmproxy")
    tornado = installed("tornado")
    return {"miniproxy_version": __version__, "python_version": list(sys.version_info[:3]),
            "proxy_distribution": "riciplay-mitmproxy", "proxy_version": fork,
            "upstream_mitmproxy_version": upstream, "tornado_version": tornado,
            "proxy_dependencies_supported": (sys.version_info >= (3, 12) and upstream is None
                and supported(fork, "==12.3.1.1") and supported(tornado, ">=6.6,<7"))}


def environment_error():
    info = runtime_info()
    if info["proxy_dependencies_supported"]:
        return None
    return ("MiniProxy requires Python 3.12+, riciplay-mitmproxy 12.3.1.1 and Tornado 6.6+. "
            "Upstream mitmproxy must not coexist with the fork (shared imports/scripts). "
            "Use a fresh virtual environment; do not uninstall shared packages automatically. "
            "See docs/setup.md for migration.")


def resolve_mitmdump(requested="mitmdump"):
    """Require the fork-owned launcher and imports in the active environment.

    A version banner alone cannot attest an external executable's Tornado or
    distribution ownership. Custom paths must identify this same launcher.
    """
    error = environment_error()
    if error:
        raise RuntimeError(error)
    distribution = metadata.distribution("riciplay-mitmproxy")
    owned = {Path(distribution.locate_file(item)).resolve() for item in distribution.files or []}
    package = find_spec("mitmproxy")
    if package is None or not package.origin or Path(package.origin).resolve() not in owned:
        raise RuntimeError("mitmproxy imports are not owned by the active riciplay-mitmproxy distribution")
    launcher = Path(sysconfig.get_path("scripts")) / ("mitmdump.exe" if os.name == "nt" else "mitmdump")
    if not launcher.is_file() or launcher.resolve() not in owned or not os.access(launcher, os.X_OK):
        raise RuntimeError("Fork-owned mitmdump launcher not found in the active environment; reinstall MiniProxy there")
    if requested != "mitmdump":
        selected = shutil.which(str(requested))
        if selected is None or Path(selected).resolve() != launcher.resolve():
            raise RuntimeError("Custom mitmdump must be the active environment's fork-owned launcher; use a fresh venv")
    return str(launcher)


def process_identity(pid):
    """Creation identity, not a command-name guess, for persisted proxy PIDs."""
    try:
        start = Path(f"/proc/{pid}/stat").read_text().rsplit(")", 1)[1].split()[19]
        boot = Path("/proc/sys/kernel/random/boot_id").read_text().strip()
        return f"{boot}:{start}"
    except (OSError, IndexError):
        if sys.platform == "darwin":
            try:
                return subprocess.check_output(["ps", "-p", str(pid), "-o", "lstart=,command="],
                                               text=True, timeout=1).strip()
            except (OSError, subprocess.SubprocessError):
                pass
        return ""


def _group_members(pgid):
    """Linux live group members with creation identities; zombies are exited."""
    if not Path("/proc").is_dir():
        return None
    members = {}
    for entry in Path("/proc").iterdir():
        if not entry.name.isdigit():
            continue
        try:
            fields = (entry / "stat").read_text().rsplit(")", 1)[1].split()
            if int(fields[2]) == pgid and fields[0] != "Z":
                members[int(entry.name)] = (process_identity(int(entry.name)), int(fields[3]))
        except (OSError, ValueError, IndexError):
            continue
    return members


def process_group_exited(pid):
    """Confirm the group is empty, never infer descendant exit from the leader.

    Without a surviving recorded identity we cannot safely signal an orphaned
    group. Callers retain state until it exits or ownership can be verified.
    """
    if not pid or pid <= 1:
        return False
    members = _group_members(pid)
    if members is not None:
        return not members
    try:
        os.killpg(pid, 0)
    except ProcessLookupError:
        return True
    except OSError:
        pass
    return False


def terminate_process_group(pid, identity, *, force=False, timeout=3.0):
    """Signal only an identified private group and confirm all members exited.

    Return False on ambiguity or failure; callers must retain ownership state.
    A leader exiting after TERM does not hide its surviving descendants.
    """
    if not pid or not identity:
        return False
    if process_identity(pid) != identity:
        return process_group_exited(pid)
    try:
        if os.getpgid(pid) != pid or os.getsid(pid) != pid:
            return False
    except (ProcessLookupError, PermissionError):
        return False
    known = _group_members(pid)
    if known is not None and (pid not in known or known[pid][0] != identity or known[pid][1] != pid):
        return False

    def alive_and_owned():
        members = _group_members(pid)
        if members is not None:
            if not members:
                return False
            # A live identified member pins the old group/session even after
            # the leader exits. Any new member must still share its private SID.
            anchor = process_identity(pid) == identity or any(
                member in known and known[member] == data for member, data in members.items()
            )
            if not anchor or any(sid != pid or not key for key, sid in members.values()):
                raise RuntimeError("Process-group ownership changed")
            known.update(members)
            return True
        try:
            os.killpg(pid, 0)
        except ProcessLookupError:
            return False
        if process_identity(pid) != identity:
            raise RuntimeError("Cannot verify surviving group without its leader")
        return True

    try:
        if not alive_and_owned():
            return True
        os.killpg(pid, signal.SIGKILL if force else signal.SIGTERM)
        for stage in range(1 if force else 2):
            deadline = time.monotonic() + timeout
            while time.monotonic() < deadline:
                if not alive_and_owned():
                    return True
                time.sleep(.05)
            if not alive_and_owned():
                return True
            if not force and stage == 0:
                os.killpg(pid, signal.SIGKILL)
        return False
    except ProcessLookupError:
        try:
            return not alive_and_owned()
        except (OSError, RuntimeError):
            return False
    except (OSError, RuntimeError):
        return False

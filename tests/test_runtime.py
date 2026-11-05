import json
from importlib import metadata
from pathlib import Path
from types import SimpleNamespace
import pytest

from miniproxy import runtime


def mock_versions(monkeypatch, *, upstream=None, fork="12.3.1.1", tornado="6.6"):
    def version(name):
        value = {"mitmproxy": upstream, "riciplay-mitmproxy": fork, "tornado": tornado}[name]
        if value is None:
            raise metadata.PackageNotFoundError(name)
        return value
    monkeypatch.setattr(runtime.metadata, "version", version)


@pytest.mark.parametrize("fork,tornado,upstream,ready", [
    ("12.3.1.1", "6.6", None, True),
    ("12.3.1.1+local", "6.6.post1", None, True),
    ("12.3.1.1", "6.6", "12.3.1", False),
    (None, "6.6", "12.3.1", False),
    ("12.3.1.1", "6.5.10", None, False),
    ("12.3.1.1", "7.0", None, False),
    ("12.3.1.1rc1", "6.6", None, False),
    ("12.3.1.1", "6.6rc1", None, False),
    ("invalid", "6.6", None, False),
])
def test_runtime_gate(monkeypatch, fork, tornado, upstream, ready):
    mock_versions(monkeypatch, upstream=upstream, fork=fork, tornado=tornado)
    assert runtime.runtime_info()["proxy_dependencies_supported"] is ready


def test_launcher_info_and_overlap_denial(monkeypatch, capsys):
    from miniproxy.__main__ import main
    from miniproxy import server
    mock_versions(monkeypatch, upstream="12.3.1")
    assert main(["launcher-info"]) == 0
    assert json.loads(capsys.readouterr().out)["upstream_mitmproxy_version"] == "12.3.1"
    monkeypatch.setattr(runtime, "environment_error", lambda: "unsafe overlap")
    monkeypatch.setattr(server.subprocess, "Popen", lambda *a, **k: pytest.fail("unsafe proxy launched"))
    assert server.start()["message"] == "unsafe overlap"


@pytest.fixture
def owned_launcher(monkeypatch, tmp_path):
    mock_versions(monkeypatch)
    launcher = tmp_path / "mitmdump"
    launcher.write_text("#!/bin/sh\nexit 0\n")
    launcher.chmod(0o700)
    package = tmp_path / "__init__.py"
    package.touch()
    distribution = SimpleNamespace(files=[launcher, package], locate_file=lambda item: item)
    monkeypatch.setattr(runtime.metadata, "distribution", lambda _: distribution)
    monkeypatch.setattr(runtime, "find_spec", lambda _: SimpleNamespace(origin=str(package)))
    monkeypatch.setattr(runtime.sysconfig, "get_path", lambda _: str(tmp_path))
    return launcher, distribution


def test_active_launcher_ignores_stale_path_and_accepts_same_file(monkeypatch, owned_launcher, tmp_path):
    launcher, _ = owned_launcher
    monkeypatch.setenv("PATH", "/unrelated/bin")
    assert runtime.resolve_mitmdump() == str(launcher)
    assert runtime.resolve_mitmdump(str(launcher)) == str(launcher)
    alias = tmp_path / "alias"
    alias.symlink_to(launcher)
    assert runtime.resolve_mitmdump(str(alias)) == str(launcher)


def test_custom_executable_cannot_bypass_runtime_gate(owned_launcher, tmp_path):
    external = tmp_path / "external"
    external.write_text("#!/bin/sh\necho 'Mitmproxy: 12.3.1.1'\n")
    external.chmod(0o700)
    with pytest.raises(RuntimeError, match="Custom mitmdump"):
        runtime.resolve_mitmdump(str(external))


def test_shadowed_import_and_unowned_script_fail_closed(monkeypatch, owned_launcher, tmp_path):
    launcher, distribution = owned_launcher
    monkeypatch.setattr(runtime, "find_spec", lambda _: SimpleNamespace(origin=str(tmp_path / "shadow.py")))
    with pytest.raises(RuntimeError, match="imports are not owned"):
        runtime.resolve_mitmdump()
    monkeypatch.setattr(runtime, "find_spec", lambda _: SimpleNamespace(origin=str(tmp_path / "__init__.py")))
    distribution.files = [Path(tmp_path / "__init__.py")]
    with pytest.raises(RuntimeError, match="launcher not found"):
        runtime.resolve_mitmdump()

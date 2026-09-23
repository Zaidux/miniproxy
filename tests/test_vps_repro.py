"""Smoke check mirroring the VPS failure: --help and version must not crash."""
import contextlib
import io

import pytest

from miniproxy.__main__ import _version, build_parser, main


def test_vps_repro_help_does_not_crash():
    # argparse exits 0 on --help; the VPS bug raised ArgumentError instead.
    with pytest.raises(SystemExit) as exc:
        buf = io.StringIO()
        with contextlib.redirect_stdout(buf):
            build_parser().parse_args(["--help"])
    assert exc.value.code == 0


def test_vps_repro_version_command(capsys, monkeypatch):
    monkeypatch.setattr(
        "miniproxy.__main__._version", lambda: "0.4.2", raising=True
    )
    assert main(["version"]) == 0
    assert capsys.readouterr().out.strip() == "0.4.2"


def test_version_falls_back_gracefully():
    assert isinstance(_version(), str)

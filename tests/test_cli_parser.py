"""Regression tests for the CLI parser itself.

Background: a duplicated ``web`` subparser crashed *every* ``miniproxy``
invocation (even ``--help``) with
``argparse.ArgumentError: conflicting subparser: web`` — but only on
machines where the parser is actually built (CI only ever called handlers,
never ``build_parser()``/``main()``). These tests build the parser and run
``main()`` with mocked handlers so a parser-construction bug is caught in
CI, not on a user's VPS.
"""
from __future__ import annotations

import pytest

from miniproxy import __main__ as cli

ALL_COMMANDS = [
    "start", "web", "stop", "status", "dashboard",
    "connect", "tui", "send", "log", "version",
]


class TestParserConstruction:
    def test_build_parser_does_not_raise(self):
        # The original crash happened here, at import/parser-build time.
        assert cli.build_parser() is not None

    def test_every_subcommand_is_registered_exactly_once(self):
        parser = cli.build_parser()
        subparsers = next(
            a for a in parser._actions if a.dest == "command"
        )
        names = list(subparsers.choices)
        assert names == ALL_COMMANDS, "duplicated or missing subcommand"

    @pytest.mark.parametrize("argv", [[c] for c in ALL_COMMANDS])
    def test_every_subcommand_parses(self, argv):
        if argv == ["send"]:
            argv = ["send", "--url", "https://example.test"]
        cli.build_parser().parse_args(argv)

    def test_start_options_copied_to_web(self):
        parsed = cli.build_parser().parse_args(
            ["web", "--port", "9999", "--dashboard-host", "0.0.0.0"]
        )
        assert parsed.port == 9999
        assert parsed.dashboard_host == "0.0.0.0"

    def test_help_works(self, capsys):
        with pytest.raises(SystemExit) as exc:
            cli.build_parser().parse_args(["--help"])
        assert exc.value.code == 0
        assert "miniproxy" in capsys.readouterr().out

    def test_port_accepts_auto_and_ints(self):
        parser = cli.build_parser()
        assert parser.parse_args(["start", "--port", "auto"]).port == "auto"
        assert parser.parse_args(["start", "--port", "9001"]).port == 9001
        assert parser.parse_args(["start"]).port == 8080
        assert parser.parse_args(
            ["start", "--dashboard-port", "auto"]).dashboard_port == "auto"
        assert parser.parse_args(["dashboard", "--port", "auto"]).port == "auto"

    def test_port_rejects_garbage(self):
        with pytest.raises(SystemExit):
            cli.build_parser().parse_args(["start", "--port", "not-a-port"])

    def test_dashboard_auto_port_is_resolved_before_app_run(self, monkeypatch):
        import miniproxy.app as appmod

        seen = {}
        monkeypatch.setattr(
            appmod.app, "run",
            lambda **kwargs: seen.update(kwargs),
        )
        assert cli.main(["dashboard", "--port", "auto"]) == 0
        assert isinstance(seen["port"], int)
        assert 1024 <= seen["port"] <= 65535


class TestMainDispatch:
    def test_version_prints_and_exits_zero(self, capsys, monkeypatch):
        monkeypatch.setattr(cli, "_version", lambda: "9.9.9-test")
        assert cli.main(["version"]) == 0
        assert capsys.readouterr().out.strip() == "9.9.9-test"

    def test_no_command_prints_help_and_exits_one(self, capsys):
        assert cli.main([]) == 1
        assert "usage" in capsys.readouterr().out.lower()

    def test_start_is_dispatched_with_parsed_options(self, monkeypatch):
        calls = {}

        def fake_start(**kwargs):
            calls.update(kwargs)
            return {"status": "started", "message": "ok",
                    "dashboard": {"url": "http://127.0.0.1:5000"}}

        import miniproxy.server as server
        monkeypatch.setattr(server, "start", fake_start)
        rc = cli.main(["start", "--port", "8123", "--scope", "*.t.example"])
        assert rc == 0
        assert calls["port"] == 8123
        assert calls["scope_hosts"] == ["*.t.example"]

    def test_start_prints_pasteable_dashboard_and_connect_urls(self, monkeypatch, capsys):
        """The URL `start` prints must be openable as-is in a browser.

        Regression: output used to say only "Web UI: <url> (mirrors tui)" —
        nothing told the user the URL is the thing to paste into the address
        bar, nor that /connect is where you wire a *different* browser up.
        The printed URL itself must be the dashboard root (server.py swaps a
        wildcard bind for a detected LAN/VPS host), never 0.0.0.0 or the
        proxy port (a browser cannot render an HTTP-proxy port).
        """
        import miniproxy.server as server

        captured_kwargs = {}

        def fake_start(**kwargs):
            captured_kwargs.update(kwargs)
            return {
                "status": "started", "message": "ok", "port": 8080,
                "dashboard": {
                    "status": "started",
                    "url": "http://192.168.1.20:5000",
                    "port": 5000,
                },
            }

        monkeypatch.setattr(server, "start", fake_start)
        monkeypatch.setattr(
            cli, "_dashboard_reachability_notes", lambda *a, **k: [])
        rc = cli.main(["start"])
        assert rc == 0
        out = capsys.readouterr().out
        # The exact URL to paste, labeled as such.
        assert "Web UI: http://192.168.1.20:5000" in out
        assert "paste this into your browser" in out
        # Connect wizard advertised next to it.
        assert "Connect: http://192.168.1.20:5000/connect" in out
        # Never advertise a bind address or the proxy port as the destination.
        assert "http://0.0.0.0" not in out
        assert ":8080/connect" not in out

    def test_start_dashboard_url_is_not_wildcard_bind(self, monkeypatch, capsys):
        """On a VPS `start` must print a host a browser can actually route to,
        not the 0.0.0.0 bind address that made the page blank."""
        import miniproxy.server as server

        monkeypatch.setattr(
            server, "start",
            lambda **kwargs: {
                "status": "started", "message": "ok", "port": 8080,
                "dashboard": {"status": "started", "url": "http://0.0.0.0:5000"},
            },
        )
        rc = cli.main(["start"])
        assert rc == 0
        out = capsys.readouterr().out
        assert "http://0.0.0.0" not in out, (
            "startup must never tell a user to paste a bind address")

    def test_start_without_dashboard_skips_url_lines(self, monkeypatch, capsys):
        import miniproxy.server as server

        monkeypatch.setattr(
            server, "start",
            lambda **kwargs: {"status": "started", "message": "ok", "port": 8080},
        )
        assert cli.main(["start", "--no-dashboard"]) == 0
        out = capsys.readouterr().out
        assert "Web UI:" not in out
        assert "Connect:" not in out

    def test_stop_dispatches_both_stops(self, monkeypatch):
        import miniproxy.server as server
        monkeypatch.setattr(server, "stop",
                            lambda: {"status": "stopped", "message": "bye"})
        monkeypatch.setattr(server, "stop_dashboard",
                            lambda: {"status": "stopped", "message": "bye"})
        assert cli.main(["stop"]) == 0

    def test_log_reads_the_db(self, monkeypatch, tmp_path, capsys):
        from miniproxy.addon.db import Database

        db = Database(str(tmp_path / "p.db"))
        rid = db.store_request("GET", "https://t.example/", {}, "")
        db.update_response(rid, 200, {}, "b", "text/plain", total_ms=12.0)
        monkeypatch.setenv("MINIPROXY_DB_PATH", str(tmp_path / "p.db"))
        assert cli.main(["log"]) == 0
        out = capsys.readouterr().out
        assert "t.example" in out

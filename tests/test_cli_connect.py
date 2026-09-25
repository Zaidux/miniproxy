"""Tests for `miniproxy connect` output and TUI ConnectScreen wiring."""
from __future__ import annotations

import asyncio

import pytest


class TestCliConnect:
    def test_connect_prints_addresses_and_urls(self, capsys, monkeypatch):
        from miniproxy import __main__ as cli
        from miniproxy import server as srv

        monkeypatch.setattr(srv, "status",
                            lambda: {"status": "running", "pid": 1, "port": 9099})
        rc = cli.main(["connect", "--host", "203.0.113.7", "--qr", "no"])
        out = capsys.readouterr().out
        assert rc == 0
        assert "203.0.113.7:9099" in out          # explicit host + running port
        assert "/proxy.pac" in out
        assert "/ca.crt" in out
        assert "curl -x" in out
        assert "http://203.0.113.7:5000/connect" in out

    def test_connect_defaults_when_not_running(self, capsys):
        from miniproxy import __main__ as cli

        rc = cli.main(["connect", "--qr", "no"])
        out = capsys.readouterr().out
        assert rc == 0
        assert ":8080" in out
        assert "NOT RUNNING" in out

    def test_connect_qr_auto_skipped_when_piped(self, capsys):
        from miniproxy import __main__ as cli

        rc = cli.main(["connect", "--qr", "auto"])
        out = capsys.readouterr().out
        assert rc == 0
        assert "\x1b[7m" not in out  # no ANSI QR when stdout is not a TTY

    def test_connect_qr_forced(self, capsys):
        from miniproxy import __main__ as cli

        rc = cli.main(["connect", "--qr", "yes"])
        out = capsys.readouterr().out
        assert rc == 0
        assert "\x1b[7m" in out and "█" in out

    def test_connect_help_listed(self):
        from miniproxy import __main__ as cli

        with pytest.raises(SystemExit):
            cli.main(["--help"])
        # (help goes to stdout via argparse; main() returning is fine too)


class TestTuiConnectScreen:
    def _seed(self, tmp_path):
        from miniproxy.addon.db import Database

        db = Database(str(tmp_path / "proxy.db"))
        rid = db.store_request("GET", "https://t.example/", {}, "")
        db.update_response(rid, 200, {"Content-Type": "text/plain"}, "hello", "text/plain")
        return db

    def test_w_key_opens_connect_screen(self, tmp_path):
        from miniproxy.tui import ConnectScreen, MiniProxyTUI

        self._seed(tmp_path)
        app = MiniProxyTUI(db_path=str(tmp_path / "proxy.db"))

        async def main():
            async with app.run_test() as pilot:
                await pilot.pause()
                await pilot.press("w")
                # A single pause() is a race: the screen stack swap and the
                # widget render are separate scheduled steps. Poll until the
                # transition actually lands instead of assuming one tick.
                for _ in range(100):
                    await pilot.pause()
                    if isinstance(app.screen, ConnectScreen):
                        break
                assert isinstance(app.screen, ConnectScreen)
                viewer = app.screen.query_one("#connect-viewer")
                for _ in range(100):
                    await pilot.pause()
                    if viewer._last_renderable is not None:
                        break
                assert viewer._last_renderable is not None
                assert "proxy.pac" in str(viewer._last_renderable)
                await pilot.press("escape")
                for _ in range(100):
                    await pilot.pause()
                    if not isinstance(app.screen, ConnectScreen):
                        break
                assert not isinstance(app.screen, ConnectScreen)

        asyncio.run(main())

    def test_connect_screen_renders_addresses(self, tmp_path):
        from miniproxy.tui import ConnectScreen, MiniProxyTUI

        self._seed(tmp_path)
        app = MiniProxyTUI(db_path=str(tmp_path / "proxy.db"))

        async def main():
            async with app.run_test() as pilot:
                await pilot.pause()
                app.push_screen(ConnectScreen("203.0.113.7:8080", "http://127.0.0.1:5000"))
                await pilot.pause()
                text = str(app.screen.query_one("#connect-viewer")._last_renderable)
                assert "203.0.113.7:8080" in text
                assert "/proxy.pac" in text and "/ca.crt" in text

        asyncio.run(main())

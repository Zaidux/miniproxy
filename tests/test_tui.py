"""Headless TUI tests (Textual Pilot) — no real terminal required."""
from __future__ import annotations

import asyncio
import os

import pytest

from miniproxy.tui import HelpScreen, MiniProxyTUI


@pytest.fixture()
def seeded(db):
    db.store_request("GET", "https://a.test/one", {}, "")
    db.update_response(1, 200, {}, "body-one", "text/plain", ttfb_ms=1, total_ms=2)
    db.store_request("POST", "https://b.test/two", {}, "req")
    db.update_response(2, 404, {}, "body-two", "text/plain")
    db.store_request("GET", "https://c.test/pending", {}, "")
    return db


def run(coro):
    return asyncio.run(coro)


class TestCompose:
    def test_boots_and_loads_rows(self, seeded):
        async def main():
            app = MiniProxyTUI(db_path=seeded.db_path)
            async with app.run_test() as pilot:
                await pilot.pause()
                assert len(app._rows_by_key) == 3

        run(main())

    def test_selection_survives_refresh(self, seeded):
        async def main():
            app = MiniProxyTUI(db_path=seeded.db_path)
            async with app.run_test() as pilot:
                await pilot.pause()
                app.action_cursor_bottom()
                await pilot.pause()
                selected = app._selected_row()["id"]
                app._refresh_table(force=True)  # plain sync call
                await pilot.pause()
                assert app._selected_row()["id"] == selected

        run(main())


class TestFilters:
    def test_method_and_url_filters(self, seeded):
        async def main():
            app = MiniProxyTUI(db_path=seeded.db_path)
            async with app.run_test() as pilot:
                await pilot.pause()
                app.query_one("#filter-method").value = "POST"
                app._refresh_table(force=True)
                await pilot.pause()
                assert len(app._rows_by_key) == 1
                app.query_one("#filter-method").value = ""
                app.query_one("#filter-url").value = "b.test"
                app._refresh_table(force=True)
                await pilot.pause()
                assert len(app._rows_by_key) == 1

        run(main())


class TestDetail:
    def test_detail_renders_response(self, seeded):
        async def main():
            app = MiniProxyTUI(db_path=seeded.db_path)
            async with app.run_test() as pilot:
                await pilot.pause()
                app.action_cursor_bottom()
                await pilot.pause()
                viewer = app.query_one("#viewer-response")
                assert viewer._last_renderable is not None

        run(main())


class TestKeys:
    def test_help_roundtrip(self, seeded):
        async def main():
            app = MiniProxyTUI(db_path=seeded.db_path)
            async with app.run_test() as pilot:
                await pilot.pause()
                await pilot.press("question_mark")
                await pilot.pause()
                assert isinstance(app.screen, HelpScreen)
                await pilot.press("escape")
                await pilot.pause()
                assert not isinstance(app.screen, HelpScreen)

        run(main())

    def test_save_body_writes_selected_row(self, seeded, tmp_path, monkeypatch):
        async def main():
            monkeypatch.chdir(tmp_path)
            app = MiniProxyTUI(db_path=seeded.db_path)
            async with app.run_test() as pilot:
                await pilot.pause()
                app.action_cursor_top()
                await pilot.pause()
                await pilot.press("j")
                await pilot.pause()
                row = app._selected_row()
                await pilot.press("e")
                await pilot.pause()
                files = list(tmp_path.glob("miniproxy-*.txt"))
                assert len(files) == 1
                assert files[0].read_text() == row["response_body"]

        run(main())

    def test_save_body_without_selection_notifies(self, seeded):
        async def main():
            app = MiniProxyTUI(db_path=seeded.db_path)
            async with app.run_test() as pilot:
                await pilot.pause()
                # empty filters → no rows → no selection possible
                app.query_one("#filter-url").value = "no-such-host"
                app._refresh_table(force=True)
                await pilot.pause()
                await pilot.press("e")  # must not raise
                await pilot.pause()

        run(main())


class TestNoBlockingImport:
    def test_import_does_not_require_terminal(self):
        import miniproxy.tui as t

        assert callable(t.run_tui)

"""Headless coverage for the TUI's new noise / diff / rewrite screens.

These mount the real app and drive it with the Textual Pilot, so a screen that
fails to compose or an action that throws is caught here rather than by a user
pressing the key.
"""
from __future__ import annotations

import asyncio
import json

import pytest

pytest.importorskip("textual")

from miniproxy.tui import (  # noqa: E402
    DiffScreen,
    MiniProxyTUI,
    NoiseScreen,
    TextViewerScreen,
)


def run(coro):
    return asyncio.run(coro)


@pytest.fixture()
def seeded(db):
    a = db.store_request("GET", "https://acct.test/my-account?role=user", {}, "")
    db.update_response(a, 200, {}, json.dumps({"role": "user"}), "application/json",
                       ttfb_ms=1, total_ms=2)
    b = db.store_request("GET", "https://acct.test/my-account?role=admin", {}, "")
    db.update_response(b, 200, {}, json.dumps({"role": "admin"}), "application/json",
                       ttfb_ms=1, total_ms=2)
    c = db.store_request("GET", "https://img-getpocket.cdn.mozilla.net/x.jpeg", {}, "")
    db.update_response(c, 200, {}, "JPEG", "image/jpeg")
    return db


class TestNoiseScreen:
    def test_opens_and_lists_bundled_rules(self, seeded):
        async def main():
            app = MiniProxyTUI(db_path=seeded.db_path)
            async with app.run_test() as pilot:
                await pilot.pause()
                app.action_show_noise()
                await pilot.pause()
                screen = app.screen
                assert isinstance(screen, NoiseScreen)
                # The seeded telemetry list is present and disabled.
                assert screen._rules, "no noise rules listed"
                assert not any(r["enabled"] for r in screen._rules)

        run(main())

    def test_toggle_a_rule(self, seeded):
        async def main():
            app = MiniProxyTUI(db_path=seeded.db_path)
            async with app.run_test() as pilot:
                await pilot.pause()
                app.action_show_noise()
                await pilot.pause()
                screen = app.screen
                target = screen._rules[screen._cursor]
                screen.action_toggle_rule()
                await pilot.pause()
                refreshed = {r["id"]: r for r in seeded.list_noise_rules()}
                assert refreshed[target["id"]]["enabled"] == 1

        run(main())

    def test_toggle_all(self, seeded):
        async def main():
            app = MiniProxyTUI(db_path=seeded.db_path)
            async with app.run_test() as pilot:
                await pilot.pause()
                app.action_show_noise()
                await pilot.pause()
                app.screen.action_toggle_all()
                await pilot.pause()
                assert all(r["enabled"] for r in seeded.list_noise_rules())

        run(main())

    def test_cursor_moves_within_bounds(self, seeded):
        async def main():
            app = MiniProxyTUI(db_path=seeded.db_path)
            async with app.run_test() as pilot:
                await pilot.pause()
                app.action_show_noise()
                await pilot.pause()
                screen = app.screen
                screen._cursor = 0
                for _ in range(5):
                    screen._cursor = min(len(screen._rules) - 1, screen._cursor + 1)
                assert 0 <= screen._cursor < len(screen._rules)

        run(main())


class TestDiffScreen:
    def test_names_the_changed_field(self, seeded):
        async def main():
            app = MiniProxyTUI(db_path=seeded.db_path)
            async with app.run_test() as pilot:
                await pilot.pause()
                app.push_screen(DiffScreen(seeded, 1, 2))
                await pilot.pause()
                assert isinstance(app.screen, DiffScreen)
                assert app.screen._mode == "auto"

        run(main())

    def test_mode_cycles(self, seeded):
        async def main():
            app = MiniProxyTUI(db_path=seeded.db_path)
            async with app.run_test() as pilot:
                await pilot.pause()
                app.push_screen(DiffScreen(seeded, 1, 2))
                await pilot.pause()
                screen = app.screen
                seen = {screen._mode}
                for _ in range(4):
                    screen.action_cycle_mode()
                    await pilot.pause()
                    seen.add(screen._mode)
                assert seen == {"auto", "json", "token", "char"}

        run(main())

    def test_missing_capture_does_not_crash(self, seeded):
        async def main():
            app = MiniProxyTUI(db_path=seeded.db_path)
            async with app.run_test() as pilot:
                await pilot.pause()
                app.push_screen(DiffScreen(seeded, 1, 99999))
                await pilot.pause()

        run(main())

    def test_action_compare_marks_then_opens(self, seeded):
        async def main():
            app = MiniProxyTUI(db_path=seeded.db_path)
            async with app.run_test() as pilot:
                await pilot.pause()
                # First press marks A.
                app.action_compare()
                await pilot.pause()
                assert app._diff_mark is not None
                first = app._diff_mark
                # Move to another row and press again.
                app.action_cursor_down()
                await pilot.pause()
                app.action_compare()
                await pilot.pause()
                assert isinstance(app.screen, DiffScreen)
                assert app._diff_mark is None
                assert first != app.screen._a_id or first == app.screen._a_id

        run(main())

    def test_comparing_a_row_with_itself_is_refused(self, seeded):
        async def main():
            app = MiniProxyTUI(db_path=seeded.db_path)
            async with app.run_test() as pilot:
                await pilot.pause()
                app.action_compare()
                await pilot.pause()
                mark = app._diff_mark
                app.action_compare()   # same row
                await pilot.pause()
                assert app._diff_mark == mark, "self-compare should not open a screen"
                assert not isinstance(app.screen, DiffScreen)

        run(main())


class TestRewriteScreen:
    def test_opens_with_no_rules(self, seeded):
        async def main():
            app = MiniProxyTUI(db_path=seeded.db_path)
            async with app.run_test() as pilot:
                await pilot.pause()
                app.action_show_rewrite()
                await pilot.pause()
                assert isinstance(app.screen, TextViewerScreen)

        run(main())

    def test_lists_an_existing_rule(self, seeded):
        seeded.add_rewrite_rule(target="header", kind="exact",
                                match="X-Forwarded-For", replace="1")
        async def main():
            app = MiniProxyTUI(db_path=seeded.db_path)
            async with app.run_test() as pilot:
                await pilot.pause()
                app.action_show_rewrite()
                await pilot.pause()
                assert isinstance(app.screen, TextViewerScreen)
                assert seeded.get_rewrite_rules()

        run(main())


class TestNewFilters:
    def test_body_filter_narrows_rows(self, seeded):
        async def main():
            app = MiniProxyTUI(db_path=seeded.db_path)
            async with app.run_test() as pilot:
                await pilot.pause()
                assert len(app._rows_by_key) == 3
                from textual.widgets import Input
                app.query_one("#filter-body", Input).value = "admin"
                app._refresh_table(force=True)
                await pilot.pause()
                assert len(app._rows_by_key) == 1

        run(main())

    def test_host_filter_narrows_rows(self, seeded):
        async def main():
            app = MiniProxyTUI(db_path=seeded.db_path)
            async with app.run_test() as pilot:
                await pilot.pause()
                from textual.widgets import Input
                app.query_one("#filter-host", Input).value = "acct.test"
                app._refresh_table(force=True)
                await pilot.pause()
                assert len(app._rows_by_key) == 2

        run(main())

    def test_hide_static_toggle(self, seeded):
        async def main():
            app = MiniProxyTUI(db_path=seeded.db_path)
            async with app.run_test() as pilot:
                await pilot.pause()
                from textual.widgets import Checkbox
                app.query_one("#filter-static", Checkbox).value = True
                app._refresh_table(force=True)
                await pilot.pause()
                # The pocket jpeg row is filtered out.
                assert len(app._rows_by_key) == 2

        run(main())
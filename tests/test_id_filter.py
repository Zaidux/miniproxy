"""Capture-id filtering across the DB layer, the JSON API and the exports.

The id selector is shared by the Live tab, the Intruder request picker and the
export menu, so it is tested once at each layer: SQL semantics, query-string
plumbing, and the guarantee that it composes with the other filters instead of
replacing them.
"""
from __future__ import annotations

import pytest

from miniproxy.addon.db import Database, parse_id_filter


@pytest.fixture()
def many(app_client):
    """A client over a DB seeded with 10 captures, ids 1..10.

    Odd ids are GET /users, even ids POST /login, so tests can tell "id
    filter" and "method filter" apart when both are applied.
    """
    client, db, _ = app_client
    for i in range(1, 11):
        rid = db.store_request(
            "GET" if i % 2 else "POST",
            f"https://api.test/users/{i}" if i % 2 else "https://api.test/login/{i}",
            {"Host": "api.test"},
            "",
        )
        db.update_response(rid, 200, {"Content-Type": "application/json"},
                           "{}", "application/json")
    return client


def _ids(payload):
    return sorted(r["id"] for r in payload)


class TestParseIdFilter:
    def test_single_id(self):
        assert parse_id_filter("42") == [("id = ?", [42])]

    def test_id_list(self):
        assert parse_id_filter("1,5,9") == [
            ("id = ?", [1]), ("id = ?", [5]), ("id = ?", [9]),
        ]

    def test_range(self):
        assert parse_id_filter("100-200") == [("id BETWEEN ? AND ?", [100, 200])]

    def test_mixed_list_and_range(self):
        assert parse_id_filter("42, 100-200") == [
            ("id = ?", [42]), ("id BETWEEN ? AND ?", [100, 200]),
        ]

    def test_reversed_range_is_normalised(self):
        """'200-100' means the same set as '100-200', not an empty result."""
        assert parse_id_filter("200-100") == parse_id_filter("100-200")

    @pytest.mark.parametrize("raw", ["", "   ", None, "abc", "-", ","])
    def test_unusable_input_is_a_noop(self, raw):
        """Garbage must not raise, and must not silently filter everything out."""
        assert parse_id_filter(raw) == []


class TestDbIdFilter:
    def test_exact(self, db):
        for _ in range(3):
            db.store_request("GET", "https://x.test/a", {}, "")
        assert [r["id"] for r in db.get_logs(ids=str(_first_id(db)))] == [_first_id(db)]

    def test_multiple_ids_are_or_ed(self, db):
        ids = [db.store_request("GET", "https://x.test/a", {}, "") for _ in range(5)]
        got = sorted(r["id"] for r in db.get_logs(limit=99, ids=f"{ids[0]},{ids[2]},{ids[4]}"))
        assert got == sorted([ids[0], ids[2], ids[4]])

    def test_range(self, db):
        ids = [db.store_request("GET", "https://x.test/a", {}, "") for _ in range(6)]
        got = sorted(r["id"] for r in db.get_logs(limit=99, ids=f"{ids[1]}-{ids[4]}"))
        assert got == sorted(ids[1:5])

    def test_composes_with_method_filter(self, db):
        even = [db.store_request("POST", "https://x.test/a", {}, "") for _ in range(3)]
        odd = [db.store_request("GET", "https://x.test/a", {}, "") for _ in range(3)]
        allids = even + odd
        lo, hi = min(allids), max(allids)
        got = [r["id"] for r in db.get_logs(limit=99, ids=f"{lo}-{hi}", method="POST")]
        assert sorted(got) == sorted(even)

    def test_count_matches_get_logs(self, db):
        ids = [db.store_request("GET", "https://x.test/a", {}, "") for _ in range(4)]
        assert db.count_logs(ids=f"{ids[1]},{ids[2]}") == 2

    def test_empty_filter_returns_everything(self, db):
        for _ in range(3):
            db.store_request("GET", "https://x.test/a", {}, "")
        assert len(db.get_logs(ids="")) == 3
        assert db.count_logs(ids="") == 3


def _first_id(db):
    return db.get_logs()[0]["id"]


class TestApiIdFilter:
    def test_list(self, many):
        assert _ids(many.get("/api/logs?id=3").get_json()) == [3]

    def test_list_of_ids(self, many):
        assert _ids(many.get("/api/logs?id=1,3,5").get_json()) == [1, 3, 5]

    def test_range(self, many):
        assert _ids(many.get("/api/logs?id=2-4").get_json()) == [2, 3, 4]

    def test_no_filter_returns_all(self, many):
        assert len(many.get("/api/logs").get_json()) == 10

    def test_composes_with_method(self, many):
        got = _ids(many.get("/api/logs?method=GET&id=1-5").get_json())
        assert got == [1, 3, 5]

    def test_composes_with_url(self, many):
        got = _ids(many.get("/api/logs?url=login&id=1-10").get_json())
        assert got == [2, 4, 6, 8, 10]

    def test_count_endpoint(self, many):
        assert many.get("/api/logs/count?id=1,3,5").get_json()["count"] == 3

    def test_count_composes(self, many):
        assert many.get("/api/logs/count?method=POST&id=1-5").get_json()["count"] == 2

    def test_garbage_is_ignored_not_fatal(self, many):
        """A half-typed range must not 500 or blank the table."""
        assert len(many.get("/api/logs?id=").get_json()) == 10
        assert len(many.get("/api/logs?id=abc").get_json()) == 10

    def test_export_har_honours_ids(self, many):
        r = many.get("/api/export/har?id=1,3")
        assert r.headers["X-Capture-Count"] == "2"
        entries = r.get_json()["log"]["entries"]
        assert len(entries) == 2

    def test_export_json_honours_ids(self, many):
        r = many.get("/api/export/json?id=2-3")
        assert r.headers["X-Capture-Count"] == "2"
        rows = r.get_json()
        assert _ids(rows) == [2, 3]


class TestTemplateWiring:
    """The page must ship the id input and route it through one builder."""

    @pytest.fixture()
    def html(self):
        from pathlib import Path

        import miniproxy

        p = Path(miniproxy.__file__).parent / "templates" / "index.html"
        return p.read_text()

    def test_live_tab_has_id_input(self, html):
        assert 'id="filter-id"' in html

    def test_id_filter_reaches_the_api(self, html):
        assert 'p.set("id", v.id)' in html

    def test_intruder_picker_exists(self, html):
        assert 'id="pick-modal"' in html
        assert 'id="pk-id"' in html

    def test_exports_share_the_filter_builder(self, html):
        """Guards the regression where exports rebuilt filters by hand and
        silently dropped the id selector."""
        assert "function exportFiltersQ() { return filtersQ(); }" in html
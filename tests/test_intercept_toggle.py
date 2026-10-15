"""The intercept addon and set_intercept() must agree on one config key.

Regression: the addon read ``intercept_enabled`` while ``set_intercept()``
wrote ``intercept``. Nothing ever wrote the key the addon read, so the
intercept toggle was a silent no-op and interception was permanently on.
"""
from __future__ import annotations

import inspect

import pytest


@pytest.fixture()
def addon_src() -> str:
    from pathlib import Path

    import miniproxy

    return (
        Path(miniproxy.__file__).parent / "addon" / "intercept_addon.py"
    ).read_text()


class TestInterceptKeyAgreement:
    def test_addon_does_not_read_the_orphan_key(self, addon_src):
        assert 'get_config("intercept_enabled"' not in addon_src

    def test_addon_reads_the_key_setter_writes(self):
        from miniproxy.addon.db import Database

        key_in_setter = inspect.getsource(Database.set_intercept)
        assert "'intercept'" in key_in_setter
        assert "intercept_enabled" not in key_in_setter

    def test_set_intercept_then_addon_reads_true(self, tmp_path):
        from miniproxy.addon.db import Database

        db = Database(tmp_path / "on.db")
        db.set_intercept(True)
        assert db.get_config("intercept", "1") == "1"

    def test_toggle_off_is_now_honoured(self, tmp_path):
        """The whole point of the fix: an explicit OFF must be readable."""
        from miniproxy.addon.db import Database

        db = Database(tmp_path / "off.db")
        db.set_intercept(False)
        assert db.get_config("intercept", "1") == "0"


class TestFreshDatabaseStaysEnabled:
    """A fresh DB has no config row; intercept must default to ON.

    ``get_intercept()`` returns False when the row is absent, so the addon
    must default the key rather than call it — otherwise every new session
    would start with interception silently disabled.
    """

    def test_fresh_db_defaults_to_enabled(self, tmp_path):
        # Explicit path: the shared conftest HOME is patched per-test, but
        # Database() resolves DB_PATH at import time, so relying on the
        # ambient home leaks state between tests.
        from miniproxy.addon.db import Database

        db = Database(tmp_path / "fresh.db")
        assert db.get_config("intercept", "1") == "1"

    def test_row_is_seeded_enabled_on_init(self, tmp_path):
        """_init_db seeds intercept='1', so a fresh DB already reads ON.

        The addon's explicit default is belt-and-braces for any DB that
        predates that seeding.
        """
        import sqlite3

        from miniproxy.addon.db import Database

        db = Database(tmp_path / "seeded.db")
        rows = dict(
            sqlite3.connect(str(db.db_path)).execute("SELECT key, value FROM config")
        )
        assert rows.get("intercept") == "1"
        assert db.get_intercept() is True


class TestStatusEndpointReportsStoredValue:
    def test_no_hardcoded_true(self):
        """The endpoint used to return a literal True regardless of state."""
        from pathlib import Path

        import miniproxy

        src = (Path(miniproxy.__file__).parent / "app.py").read_text()
        assert '"intercept_enabled": True' not in src
        assert '"intercept_enabled": db.get_intercept()' in src
"""SQLite database handler for MiniProxy — stores request logs, intruder results, and proxy config."""

import json
import os
import sqlite3
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any

DB_DIR = Path(__file__).resolve().parent
# Standalone default: the user's home state dir, NOT the package directory
# (site-packages is frequently read-only for the invoking user). The Riciplay
# CLI bundle variant pins this inside its own tree; mitmdump callers
# override via MINIPROXY_DB_PATH either way.
DB_PATH = Path.home() / ".miniproxy" / "proxy.db"

DEFAULT_MAX_ROWS = 5_000
DEFAULT_MAX_AGE_DAYS = 7
DEFAULT_MAX_DB_BYTES = 50 * 1024 * 1024


class Database:
    """Thread-safe SQLite interface using WAL mode (safe for concurrent readers)."""

    def __init__(
        self,
        db_path: str | Path | None = None,
        *,
        max_rows: int | None = None,
        max_age_days: int | None = None,
        max_db_bytes: int | None = None,
    ) -> None:
        self.db_path = str(db_path or os.environ.get("MINIPROXY_DB_PATH") or DB_PATH)
        Path(self.db_path).parent.mkdir(parents=True, exist_ok=True)
        self.max_rows = max_rows if max_rows is not None else int(os.environ.get("MINIPROXY_MAX_ROWS", DEFAULT_MAX_ROWS))
        self.max_age_days = max_age_days if max_age_days is not None else int(os.environ.get("MINIPROXY_MAX_AGE_DAYS", DEFAULT_MAX_AGE_DAYS))
        self.max_db_bytes = max_db_bytes if max_db_bytes is not None else int(os.environ.get("MINIPROXY_MAX_DB_BYTES", DEFAULT_MAX_DB_BYTES))
        self._init_db()

    def _connect(self) -> sqlite3.Connection:
        conn = sqlite3.connect(self.db_path, timeout=10)
        conn.row_factory = sqlite3.Row
        conn.execute("PRAGMA journal_mode=WAL")
        conn.execute("PRAGMA foreign_keys=ON")
        return conn

    def _init_db(self) -> None:
        conn = self._connect()
        conn.executescript("""
            CREATE TABLE IF NOT EXISTS requests (
                id          INTEGER PRIMARY KEY AUTOINCREMENT,
                timestamp   TEXT NOT NULL,
                method      TEXT NOT NULL,
                url         TEXT NOT NULL,
                headers     TEXT,
                body        TEXT,
                response_code    INTEGER,
                response_headers TEXT,
                response_body    TEXT,
                content_type     TEXT,
                ttfb_ms          REAL,
                total_ms         REAL
            );

            CREATE TABLE IF NOT EXISTS intruder_results (
                id                INTEGER PRIMARY KEY AUTOINCREMENT,
                request_id        INTEGER NOT NULL,
                timestamp         TEXT NOT NULL,
                payload           TEXT,
                method            TEXT NOT NULL,
                url               TEXT NOT NULL,
                headers           TEXT,
                body              TEXT,
                response_code     INTEGER,
                response_body     TEXT,
                response_headers  TEXT,
                ttfb_ms           REAL,
                FOREIGN KEY (request_id) REFERENCES requests(id)
            );

            CREATE TABLE IF NOT EXISTS config (
                key   TEXT PRIMARY KEY,
                value TEXT
            );
        """)
        # Deployed session DBs predate the timing columns — migrate in place.
        # Only duplicate-column errors are ignorable: swallowing everything
        # (e.g. "database is locked") would silently skip the migration and
        # fail later with "no such column" mid-capture.
        for column in ("ttfb_ms", "total_ms"):
            try:
                conn.execute(f"ALTER TABLE requests ADD COLUMN {column} REAL")
            except sqlite3.OperationalError as exc:
                if "duplicate column" not in str(exc).lower():
                    raise
        try:
            conn.execute("ALTER TABLE intruder_results ADD COLUMN ttfb_ms REAL")
        except sqlite3.OperationalError as exc:
            if "duplicate column" not in str(exc).lower():
                raise
        try:
            conn.execute("ALTER TABLE intruder_results ADD COLUMN total_ms REAL")
        except sqlite3.OperationalError as exc:
            if "duplicate column" not in str(exc).lower():
                raise
        conn.execute(
            "INSERT OR IGNORE INTO config (key, value) VALUES ('intercept', '1')"
        )
        conn.commit()
        conn.close()

    def prune(self) -> int:
        """Bound persisted captures by age, row count, and approximate DB size."""
        conn = self._connect()
        removed = 0
        if self.max_age_days > 0:
            cutoff = (datetime.now(timezone.utc) - timedelta(days=self.max_age_days)).isoformat()
            conn.execute(
                "DELETE FROM intruder_results WHERE request_id IN "
                "(SELECT id FROM requests WHERE timestamp < ?)", (cutoff,),
            )
            cur = conn.execute("DELETE FROM requests WHERE timestamp < ?", (cutoff,))
            removed += max(cur.rowcount, 0)
        if self.max_rows > 0:
            conn.execute(
                "DELETE FROM intruder_results WHERE request_id IN "
                "(SELECT id FROM requests WHERE id NOT IN "
                "(SELECT id FROM requests ORDER BY id DESC LIMIT ?))",
                (self.max_rows,),
            )
            cur = conn.execute(
                "DELETE FROM requests WHERE id NOT IN "
                "(SELECT id FROM requests ORDER BY id DESC LIMIT ?)",
                (self.max_rows,),
            )
            removed += max(cur.rowcount, 0)
        if self.max_db_bytes > 0:
            page_size = int(conn.execute("PRAGMA page_size").fetchone()[0])
            page_count = int(conn.execute("PRAGMA page_count").fetchone()[0])
            while page_size * page_count > self.max_db_bytes:
                ids = conn.execute("SELECT id FROM requests ORDER BY id LIMIT 100").fetchall()
                if not ids:
                    break
                conn.executemany("DELETE FROM intruder_results WHERE request_id=?", ids)
                conn.executemany("DELETE FROM requests WHERE id=?", ids)
                removed += len(ids)
                conn.commit()
                conn.execute("PRAGMA wal_checkpoint(TRUNCATE)")
                conn.execute("VACUUM")
                page_count = int(conn.execute("PRAGMA page_count").fetchone()[0])
        conn.commit()
        conn.close()
        return removed

    # ── Request / Response ──────────────────────────────────────────────

    def store_request(
        self,
        method: str,
        url: str,
        headers: dict[str, str],
        body: str,
    ) -> int:
        conn = self._connect()
        cur = conn.execute(
            "INSERT INTO requests (timestamp, method, url, headers, body) "
            "VALUES (?, ?, ?, ?, ?)",
            (
                datetime.now(timezone.utc).isoformat(),
                method,
                url,
                json.dumps(headers),
                body or "",
            ),
        )
        conn.commit()
        row_id: int = cur.lastrowid
        conn.close()
        self.prune()
        return row_id

    def update_response(
        self,
        req_id: int,
        code: int,
        headers: dict[str, str],
        body: str,
        content_type: str | None,
        ttfb_ms: float | None = None,
        total_ms: float | None = None,
    ) -> None:
        conn = self._connect()
        conn.execute(
            "UPDATE requests SET response_code=?, response_headers=?, "
            "response_body=?, content_type=?, ttfb_ms=?, total_ms=? WHERE id=?",
            (
                code,
                json.dumps(headers),
                (body or "")[:100_000],
                content_type or "",
                ttfb_ms,
                total_ms,
                req_id,
            ),
        )
        conn.commit()
        conn.close()

    def update_response_light(
        self,
        req_id: int,
        code: int,
        headers: dict[str, str],
        content_type: str | None,
        ttfb_ms: float | None = None,
        total_ms: float | None = None,
    ) -> None:
        conn = self._connect()
        conn.execute(
            "UPDATE requests SET response_code=?, response_headers=?, "
            "content_type=?, ttfb_ms=?, total_ms=? WHERE id=?",
            (
                code,
                json.dumps(headers),
                content_type or "",
                ttfb_ms,
                total_ms,
                req_id,
            ),
        )
        conn.commit()
        conn.close()

    def update_response_error(self, req_id: int, error: str) -> None:
        """Mark a stored request as failed with an explicit error marker.

        Uses response_code=0 (never a real HTTP status) plus a JSON error
        note in response_headers so flow readers can distinguish transport
        failures from pending responses.
        """
        conn = self._connect()
        conn.execute(
            "UPDATE requests SET response_code=0, response_headers=?, "
            "content_type='' WHERE id=? AND response_code IS NULL",
            (
                json.dumps({"_error": str(error or "flow_error")[:200]}),
                req_id,
            ),
        )
        conn.commit()
        conn.close()

    def get_logs(self, limit: int = 100, since_id: int = 0) -> list[dict[str, Any]]:
        conn = self._connect()
        rows = conn.execute(
            "SELECT * FROM requests WHERE id > ? ORDER BY id DESC LIMIT ?",
            (since_id, limit),
        ).fetchall()
        conn.close()
        return [dict(r) for r in rows]

    def count_logs(self) -> int:
        """Total captured requests in this session DB (for pagination)."""
        conn = self._connect()
        total = conn.execute("SELECT COUNT(*) FROM requests").fetchone()[0]
        conn.close()
        return int(total)

    def get_request(self, req_id: int) -> dict[str, Any] | None:
        conn = self._connect()
        row = conn.execute(
            "SELECT * FROM requests WHERE id=?", (req_id,)
        ).fetchone()
        conn.close()
        return dict(row) if row else None

    # ── Proxy state ────────────────────────────────────────────────────

    def set_intercept(self, enabled: bool) -> None:
        conn = self._connect()
        conn.execute(
            "INSERT OR REPLACE INTO config (key, value) VALUES ('intercept', ?)",
            ("1" if enabled else "0"),
        )
        conn.commit()
        conn.close()

    def get_intercept(self) -> bool:
        conn = self._connect()
        row = conn.execute(
            "SELECT value FROM config WHERE key='intercept'"
        ).fetchone()
        conn.close()
        return row is not None and row["value"] == "1"

    def set_config(self, key: str, value: str) -> None:
        """Persist a named MiniProxy setting."""
        conn = self._connect()
        conn.execute(
            "INSERT OR REPLACE INTO config (key, value) VALUES (?, ?)",
            (key, value),
        )
        conn.commit()
        conn.close()

    def get_config(self, key: str, default: str = "") -> str:
        """Read a named MiniProxy setting, returning ``default`` if absent."""
        conn = self._connect()
        row = conn.execute(
            "SELECT value FROM config WHERE key=?", (key,)
        ).fetchone()
        conn.close()
        return str(row["value"]) if row is not None else default

    # ── Intruder results ───────────────────────────────────────────────

    def store_intruder_results(self, results: list[dict[str, Any]]) -> None:
        conn = self._connect()
        now = datetime.now(timezone.utc).isoformat()
        for r in results:
            conn.execute(
                "INSERT INTO intruder_results "
                "(request_id, timestamp, payload, method, url, headers, "
                "body, response_code, response_body, response_headers, ttfb_ms, total_ms) "
                "VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
                (
                    r.get("request_id", 0),
                    now,
                    r.get("payload", ""),
                    r.get("method", "GET"),
                    r.get("url", ""),
                    json.dumps(r.get("headers", {})),
                    r.get("body", ""),
                    r.get("response_code", 0),
                    (r.get("response_body", "") or "")[:100_000],
                    json.dumps(r.get("response_headers", {})),
                    r.get("ttfb_ms"),
                    r.get("total_ms"),
                ),
            )
        conn.commit()
        conn.close()

    def get_intruder_results(self, request_id: int) -> list[dict[str, Any]]:
        conn = self._connect()
        rows = conn.execute(
            "SELECT * FROM intruder_results WHERE request_id=? ORDER BY id",
            (request_id,),
        ).fetchall()
        conn.close()
        return [dict(r) for r in rows]

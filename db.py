"""SQLite database handler for MiniProxy — stores request logs, intruder results, and proxy config."""

import json
import sqlite3
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

DB_DIR = Path(__file__).resolve().parent
DB_PATH = DB_DIR / "proxy.db"


class Database:
    """Thread-safe SQLite interface using WAL mode (safe for concurrent readers)."""

    def __init__(self, db_path: str | Path | None = None) -> None:
        self.db_path = str(db_path or DB_PATH)
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
                content_type     TEXT
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
                FOREIGN KEY (request_id) REFERENCES requests(id)
            );

            CREATE TABLE IF NOT EXISTS config (
                key   TEXT PRIMARY KEY,
                value TEXT
            );
        """)
        conn.execute(
            "INSERT OR IGNORE INTO config (key, value) VALUES ('intercept', '1')"
        )
        conn.commit()
        conn.close()

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
        return row_id

    def update_response(
        self,
        req_id: int,
        code: int,
        headers: dict[str, str],
        body: str,
        content_type: str | None,
    ) -> None:
        conn = self._connect()
        conn.execute(
            "UPDATE requests SET response_code=?, response_headers=?, "
            "response_body=?, content_type=? WHERE id=?",
            (
                code,
                json.dumps(headers),
                (body or "")[:100_000],
                content_type or "",
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

    # ── Intruder results ───────────────────────────────────────────────

    def store_intruder_results(self, results: list[dict[str, Any]]) -> None:
        conn = self._connect()
        now = datetime.now(timezone.utc).isoformat()
        for r in results:
            conn.execute(
                "INSERT INTO intruder_results "
                "(request_id, timestamp, payload, method, url, headers, "
                "body, response_code, response_body, response_headers) "
                "VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
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

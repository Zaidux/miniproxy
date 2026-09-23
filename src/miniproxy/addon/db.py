"""SQLite database handler for MiniProxy — stores request logs, intruder results, and proxy config."""

import json
import os
import sqlite3
import threading
import time
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
# Bodies are capped so one huge upload/download cannot balloon the DB.
MAX_BODY_BYTES = 100_000

STATUS_CLASSES = {"2", "3", "4", "5", "0", "pending"}


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
        self.max_body_bytes = int(os.environ.get("MINIPROXY_MAX_BODY_BYTES", MAX_BODY_BYTES))
        self._init_db()
        # Prune at most once per interval — running it inside store_request
        # put DELETEs (and, when over the size cap, a full VACUUM) into the
        # capture hot path, stalling the proxy and risking lock contention.
        self._min_prune_interval = 60.0
        self._last_prune = 0.0
        self._prune_lock = threading.Lock()

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

            CREATE TABLE IF NOT EXISTS devices (
                id         INTEGER PRIMARY KEY AUTOINCREMENT,
                name       TEXT NOT NULL,
                ip         TEXT,
                user_agent TEXT,
                first_seen TEXT NOT NULL,
                last_seen  TEXT NOT NULL,
                note       TEXT
            );

            CREATE UNIQUE INDEX IF NOT EXISTS idx_devices_identity
                ON devices (name, ip);
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
        # Track original body sizes so clients can flag truncated captures.
        for column, decl in (
            ("request_body_len", "INTEGER"),
            ("response_body_len", "INTEGER"),
        ):
            try:
                conn.execute(f"ALTER TABLE requests ADD COLUMN {column} {decl}")
            except sqlite3.OperationalError as exc:
                if "duplicate column" not in str(exc).lower():
                    raise
        conn.execute(
            "INSERT OR IGNORE INTO config (key, value) VALUES ('intercept', '1')"
        )
        conn.commit()
        conn.close()

    def prune(self) -> int:
        """Bound persisted captures by age, row count, and approximate DB size.

        Note: this can run VACUUM (seconds on a large DB). It is throttled
        via :meth:`prune_if_needed` so the capture path never blocks on it.
        """
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
                (int(self.max_rows),),
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
                try:
                    conn.execute("PRAGMA wal_checkpoint(TRUNCATE)")
                    conn.execute("VACUUM")
                except sqlite3.Error:
                    # Reclaiming disk space is best-effort; a reader holding
                    # the DB (TUI poll, dashboard) can legitimately block
                    # VACUUM. Deletes above already bounded the row count.
                    pass
                page_count = int(conn.execute("PRAGMA page_count").fetchone()[0])
        conn.commit()
        conn.close()
        return removed

    # ── Request / Response ──────────────────────────────────────────────

    def prune_if_needed(self) -> None:
        """Run prune() at most once per interval (cheap no-op otherwise).

        Called from store_request; the throttle keeps the per-request cost
        to a float compare. The lock prevents concurrent proxy threads from
        double-pruning.
        """
        now = time.monotonic()
        if now - self._last_prune < self._min_prune_interval:
            return
        with self._prune_lock:
            now = time.monotonic()
            if now - self._last_prune < self._min_prune_interval:
                return
            self._last_prune = now
            try:
                self.prune()
            except sqlite3.Error:
                # Never let housekeeping break capture; try again next cycle.
                pass

    def store_request(
        self,
        method: str,
        url: str,
        headers: dict[str, str],
        body: str,
    ) -> int:
        conn = self._connect()
        cur = conn.execute(
            "INSERT INTO requests (timestamp, method, url, headers, body, request_body_len) "
            "VALUES (?, ?, ?, ?, ?, ?)",
            (
                datetime.now(timezone.utc).isoformat(),
                method,
                url,
                json.dumps(headers),
                # Cap request bodies like response bodies — a multi-MB upload
                # would otherwise be stored whole and balloon the DB.
                (body or "")[:self.max_body_bytes],
                len(body or ""),
            ),
        )
        conn.commit()
        row_id: int = cur.lastrowid
        conn.close()
        self.prune_if_needed()
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
            "response_body=?, response_body_len=?, content_type=?, ttfb_ms=?, total_ms=? WHERE id=?",
            (
                code,
                json.dumps(headers),
                (body or "")[:self.max_body_bytes],
                len(body or ""),
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

    def get_logs(
        self,
        limit: int = 100,
        since_id: int = 0,
        *,
        method: str = "",
        status_class: str = "",
        url_substr: str = "",
    ) -> list[dict[str, Any]]:
        """Newest-first capture listing with server-side filtering.

        Filters (applied in SQL so exports of huge DBs stay bounded):
        * ``method`` — exact, case-insensitive
        * ``status_class`` — ``2``..``5`` (HTTP class), ``0`` (transport
          error), ``pending`` (no response yet)
        * ``url_substr`` — case-insensitive substring
        """
        clauses = ["id > ?"]
        params: list[Any] = [since_id]
        if method:
            clauses.append("UPPER(method) = ?")
            params.append(method.upper())
        if status_class:
            sc = str(status_class).lower()
            if sc not in STATUS_CLASSES:
                raise ValueError(f"invalid status_class: {status_class!r}")
            if sc == "pending":
                clauses.append("response_code IS NULL")
            elif sc == "0":
                clauses.append("response_code = 0")
            else:
                base = int(sc) * 100
                clauses.append("response_code BETWEEN ? AND ?")
                params.extend((base, base + 99))
        if url_substr:
            clauses.append("INSTR(LOWER(url), ?) > 0")
            params.append(url_substr.lower())
        conn = self._connect()
        rows = conn.execute(
            "SELECT *, (response_code IS NOT NULL) AS has_response "
            f"FROM requests WHERE {' AND '.join(clauses)} "
            "ORDER BY id DESC LIMIT ?",
            (*params, limit),
        ).fetchall()
        conn.close()
        return [dict(r) for r in rows]

    def count_logs(self, **filters: Any) -> int:
        """Total captured requests (for pagination). Accepts the same
        server-side filters as :meth:`get_logs`."""
        if not filters:
            conn = self._connect()
            total = conn.execute("SELECT COUNT(*) FROM requests").fetchone()[0]
            conn.close()
            return int(total)
        return len(self.get_logs(limit=10_000_000, **filters))

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
            try:
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
            except sqlite3.Error:
                # FK violation (capture pruned mid-attack) or a malformed
                # row must not lose the whole batch — skip and continue.
                continue
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

    # ── Connected devices ──────────────────────────────────────────

    def register_device(
        self,
        name: str,
        ip: str | None = None,
        user_agent: str | None = None,
    ) -> int:
        """Save a connected device, upserting on (name, ip).

        Pairing the same device twice (e.g. a phone revisiting the wizard
        from the same address) refreshes ``last_seen`` instead of stacking
        duplicate rows; the same name from a *different* IP is a separate
        entry (that is genuinely a different device/position). A missing IP
        is normalized to ``""`` — SQLite treats NULLs as distinct in unique
        indexes, so NULL IPs would never upsert.
        """
        ip = (ip or "").strip()[:45]
        now = datetime.now(timezone.utc).isoformat()
        conn = self._connect()
        try:
            cur = conn.execute(
                "INSERT INTO devices (name, ip, user_agent, first_seen, last_seen) "
                "VALUES (?, ?, ?, ?, ?) "
                "ON CONFLICT(name, ip) DO UPDATE SET "
                "user_agent=excluded.user_agent, last_seen=excluded.last_seen",
                (name, ip, user_agent, now, now),
            )
            # On the DO UPDATE path SQLite does not refresh lastrowid, so
            # fetch the row's real id explicitly.
            row: tuple | None = conn.execute(
                "SELECT id FROM devices WHERE name=? AND ip=?",
                (name, ip),
            ).fetchone()
            conn.commit()
        finally:
            conn.close()
        if row is None:  # pragma: no cover - upsert guarantees a row
            raise RuntimeError("register_device: device row vanished after upsert")
        return int(row[0])

    def get_devices(self, limit: int = 100) -> list[dict[str, Any]]:
        """Saved devices, most recently active first."""
        conn = self._connect()
        rows = conn.execute(
            "SELECT * FROM devices ORDER BY last_seen DESC LIMIT ?",
            (max(int(limit), 1),),
        ).fetchall()
        conn.close()
        return [dict(r) for r in rows]

    def remove_device(self, device_id: int) -> bool:
        """Forget one device; True if a row was deleted."""
        conn = self._connect()
        cur = conn.execute("DELETE FROM devices WHERE id=?", (int(device_id),))
        conn.commit()
        conn.close()
        return bool(cur.rowcount)

    def clear_devices(self) -> int:
        """Forget every saved device; returns rows removed."""
        conn = self._connect()
        cur = conn.execute("DELETE FROM devices")
        conn.commit()
        conn.close()
        return max(cur.rowcount, 0)

    # ── Maintenance / export helpers ───────────────────────────────────

    def clear(self) -> int:
        """Delete every capture and intruder result. Returns rows removed."""
        conn = self._connect()
        cur = conn.execute("DELETE FROM intruder_results")
        removed_intruder = max(cur.rowcount, 0)
        cur = conn.execute("DELETE FROM requests")
        removed = max(cur.rowcount, 0)
        conn.commit()
        try:
            conn.execute("PRAGMA wal_checkpoint(TRUNCATE)")
        except sqlite3.Error:
            pass
        conn.close()
        _ = removed_intruder
        return removed

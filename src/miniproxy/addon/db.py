"""SQLite database handler for MiniProxy — stores request logs, intruder results, and proxy config."""

import json
import os
import re
import sqlite3
import threading
import time
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any
from urllib.parse import urlsplit

DB_DIR = Path(__file__).resolve().parent
# Standalone default: the user's home state dir, NOT the package directory
# (site-packages is frequently read-only for the invoking user). The Riciplay
# CLI bundle variant pins this inside its own tree; mitmdump callers
# override via MINIPROXY_DB_PATH either way.
DB_PATH = Path.home() / ".miniproxy" / "proxy.db"

class NoiseBackupError(RuntimeError):
    """Raised when a noise cleanup cannot write its safety backup.

    Deletion is the irreversible half of a cleanup, so a failed backup aborts
    it rather than silently deleting without a way back.
    """


DEFAULT_MAX_ROWS = 5_000
DEFAULT_MAX_AGE_DAYS = 7
DEFAULT_MAX_DB_BYTES = 50 * 1024 * 1024
# Bodies are capped so one huge upload/download cannot balloon the DB.
MAX_BODY_BYTES = 100_000

STATUS_CLASSES = {"2", "3", "4", "5", "0", "pending"}

# ── Noise model ──────────────────────────────────────────────────────
# A browser session drags in a long tail of traffic that is never part of the
# assessment: telemetry pings, ad beacons, "new tab" thumbnails, font and
# analytics requests. On a typical Firefox session that outnumbers the actual
# target traffic 10:1 (measured on a real Web-Security-Academy run: 119
# captured rows, 12 on-target). Three layers tame it:
#   1. capture-time  — NoiseRules.is_noise() before the row is ever written
#   2. query-time    — hide_static / exclude_host filters in get_logs()
#   3. cleanup-time  — clean_noise() bulk-deletes rows matching the rules

# Extensions that are assets, not API surface. Matching is on the URL path
# only — a dynamic route like /api/image.png that returns JSON is far more
# interesting than a missing .png on a non-API host, and the content-type
# check below covers that case.
STATIC_EXTENSIONS = frozenset({
    # images
    "png", "jpg", "jpeg", "gif", "webp", "avif", "bmp", "ico", "svg", "tif", "tiff",
    # fonts
    "woff", "woff2", "ttf", "otf", "eot",
    # style / script
    "css", "js", "mjs", "map",
    # media
    "mp3", "mp4", "webm", "ogg", "wav", "avif", "aac", "flac",
})

# Content types that are always assets. Images/fonts get filtered by MIME even
# when the URL has no extension (CDN URLs often look like /132x132/filters:...).
STATIC_CONTENT_TYPES = frozenset({
    "image/", "font/", "audio/", "video/",
    "text/css", "application/javascript", "text/javascript",
})

# Hosts that are pure telemetry/ads for common browsers. Seeded as *disabled*
# rules so nothing is dropped until the user opts in (a host list is a policy
# decision — Firefox Patchlist users legitimately probe some of these).
DEFAULT_NOISE_HOSTS = (
    # Firefox telemetry / update / news / Pocket / ad-serving
    "incoming.telemetry.mozilla.org",
    "*.telemetry.services.mozilla.com",
    "*.services.mozilla.com",
    "addons.mozilla.org",
    "cont.services.mozilla.com",
    "push.services.mozilla.com",
    "firefox.settings.services.mozilla.com",
    "activity-stream.telemetry.services.mozilla.com",
    "img-getpocket.cdn.mozilla.net",
    "ads.mozilla.org",
    "detectportal.firefox.com",
    "browser-search.services.mozilla.com",
    # Ad networks / analytics
    "googleads.g.doubleclick.net",
    "doubleclick.net",
    "google-analytics.com",
    "*.google-analytics.com",
    "app-measurement.com",
    "sb.scorecardresearch.com",
    "sbjs.g.doubleclick.net",
    # Google background services
    "safebrowsing.googleapis.com",
    "update.googleapis.com",
    "clientservices.googleapis.com",
    "optimizationguide-pa.googleapis.com",
    "content-autofill.googleapis.com",
    # Microsoft / Apple background services
    "vortex.data.microsoft.com",
    "watson.telemetry.microsoft.com",
    "browser.events.data.msn.com",
    "settings-win.data.microsoft.com",
)

# Valid highlight colors (Burp-style palette). Stored as hex so the UI can
# render them directly and so an unknown value can be rejected at the API edge.
HIGHLIGHT_COLORS = (
    "#f85149",  # red
    "#d29922",  # orange
    "#e3b341",  # yellow
    "#3fb950",  # green
    "#39c5cf",  # cyan
    "#58a6ff",  # blue
    "#bc8cff",  # magenta
    "#f778ba",  # pink
)


def is_valid_highlight(color: str | None) -> bool:
    """True for ``None``/``""`` (clear) or a palette color (case-insensitive)."""
    if not color:
        return True
    return str(color).strip().lower() in HIGHLIGHT_COLORS


# The SQL twin of the host filter. Matching must stop at the end of the host,
# not the end of the URL: `host=render` must not match
# `https://target.example/render`. The host is the slice between '://' and the
# first '/', '?' or '#'; those three characters are not valid in a hostname, so
# their lowest position bounds the slice.
# The SQL twin of the host filter. Matching must stop at the end of the host,
# not the end of the URL: `host=render` must not match
# `https://target.example/render`. The host is the slice between '://' and the
# first '/', '?' or '#' — none of those three characters may appear in a
# hostname, so the earliest of them bounds the slice.
_HOST_SQL_EXPR = """
  CASE WHEN INSTR(url, '://') = 0 THEN ''
  ELSE SUBSTR(
         SUBSTR(url, INSTR(url, '://') + 3),
         1,
         MIN(
           COALESCE(NULLIF(INSTR(SUBSTR(url, INSTR(url, '://') + 3), '/'), 0), 999999),
           COALESCE(NULLIF(INSTR(SUBSTR(url, INSTR(url, '://') + 3), '?'), 0), 999999),
           COALESCE(NULLIF(INSTR(SUBSTR(url, INSTR(url, '://') + 3), '#'), 0), 999999)
         ) - 1
       )
  END
"""
# Wrap the expression in a MATCH so a param can be bound once per use.
_HOST_SQL_MATCH = f"(INSTR(LOWER({_HOST_SQL_EXPR}), ?) > 0)"
# A hostname-looking value matches on label boundaries: the host itself or a
# subdomain of it. Plain substring matching made `host=example.com` also return
# `notexample.com` and `example.com.evil`, which in a capture tool means
# inspecting the wrong target's traffic; plain equality broke the useful
# `mozilla.org` -> `incoming.telemetry.mozilla.org` case. A bare fragment (no
# dot) keeps substring behaviour.
_HOST_SQL_DOMAIN = f"(LOWER({_HOST_SQL_EXPR}) = ? OR LOWER({_HOST_SQL_EXPR}) LIKE '%.' || ?)"


def _static_sql() -> str:
    """SQL twin of :func:`is_static_asset`, used by the ``hide_static`` filter.

    Mirrors the three-way resolution exactly: a known asset MIME matches, a
    known non-asset MIME does not, and only an absent type falls back to the
    URL extension. ``content_type IS NULL OR = ''`` covers pending flows and
    304s, which are the rows with no type recorded.

    Asserted in lockstep with the Python version by
    ``test_sql_hide_static_matches_python``.
    """
    # COALESCE everywhere: with a NULL content_type the whole expression used
    # to evaluate to NULL, and `WHERE NOT NULL` drops the row. So every capture
    # with no recorded content type vanished under "Hide static", even API
    # traffic with no extension.
    ct = "COALESCE(LOWER(content_type), '')"
    asset_mimes = " OR ".join(
        f"{ct} LIKE '{p}%'" for p in sorted(STATIC_CONTENT_TYPES)
    )
    # Match the extension at the end of the *path*, not the end of the URL:
    # `app.js?v=1` is static (the Python twin parses the path and says so), but
    # `LIKE '%.js'` missed it, so the SQL filter and the client-side filter
    # disagreed about cache-busted assets. Strip a query/fragment first by
    # matching ".<ext>" followed by end-of-string, '?' or '#'.
    exts = " OR ".join(
        f"(LOWER(url) LIKE '%.{e}' OR LOWER(url) LIKE '%.{e}?%'"
        f" OR LOWER(url) LIKE '%.{e}#%')"
        for e in sorted(STATIC_EXTENSIONS)
    )
    # The whole expression must be parenthesised. The filter is applied as
    # "NOT " + this, and `NOT (mimes) OR (ext)` binds as `(NOT mimes) OR ext`,
    # so a row with a NULL content type matched through the second disjunct and
    # "Hide static" never hid extension-only rows (pending flows, 304s).
    return (
        "((" + asset_mimes + ")"
        " OR (" + ct + " = ''"
        " AND (" + exts + ")))"
    )


def host_of(url: str) -> str:
    """Netloc of a URL, lowercased, port and userinfo stripped."""
    try:
        netloc = urlsplit(url or "").netloc
    except ValueError:
        return ""
    if "@" in netloc:
        netloc = netloc.rsplit("@", 1)[1]
    if netloc.startswith("["):  # IPv6 literal
        return netloc.split("]", 1)[0] + "]"
    return netloc.rsplit(":", 1)[0].lower() if ":" in netloc else netloc.lower()


def is_static_asset(url: str = "", content_type: str = "") -> bool:
    """Heuristic: is this capture a static asset rather than API/app traffic?

    Resolution order:
      1. A known **asset** content type (``image/*``, ``font/*``, ``text/css``,
         ...) -> True.
      2. A known **non-asset** content type (``application/json``,
         ``text/html``, ...) -> False. This is the important case: a dynamic
         route like ``/api/image.png`` that returns JSON is API surface, and
         hiding it on the strength of its filename alone would hide a bug.
      3. No content type (pending flow, 304, or a non-captured body) -> fall
         back to the URL extension.

    The content type is checked first because it is the more reliable signal:
    CDN asset URLs frequently carry no recognisable extension at all.
    """
    ct = (content_type or "").split(";")[0].strip().lower()
    if ct:
        if any(ct.startswith(p) for p in STATIC_CONTENT_TYPES):
            return True
        # A definite non-asset type wins over the filename.
        return False
    try:
        path = urlsplit(url or "").path
    except ValueError:
        path = ""
    tail = path.rsplit("/", 1)[-1]
    if "." in tail:
        ext = tail.rsplit(".", 1)[-1].lower()
        # Guard against query-ish junk leaking into the path component.
        if ext.isalnum() and ext in STATIC_EXTENSIONS:
            return True
    return False


def parse_id_filter(raw: str) -> list[tuple[str, list[Any]]]:
    """Translate an id-filter expression into SQL ``(clause, params)`` pairs.

    Accepts a comma/space separated mix of exact ids and inclusive ranges:
    ``"42"``, ``"1,5,9"``, ``"100-200"``, ``"42, 100-200"``.  Reversed
    ranges (``200-100"``) are normalised rather than silently matching
    nothing, because a user who types them backwards means "between these".

    Returns ``[]`` when nothing usable was supplied, so callers can treat an
    empty box as "no id filter" instead of erroring.
    """
    out: list[tuple[str, list[Any]]] = []
    for tok in re.split(r"[,\s]+", str(raw or "").strip()):
        if not tok:
            continue
        rng = re.fullmatch(r"(\d{1,18})\s*-\s*(\d{1,18})", tok)
        if rng:
            lo, hi = int(rng.group(1)), int(rng.group(2))
            if lo > hi:
                lo, hi = hi, lo
            out.append(("id BETWEEN ? AND ?", [lo, hi]))
            continue
        if re.fullmatch(r"\d{1,18}", tok):
            out.append(("id = ?", [int(tok)]))
    return out


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
        self._harden_perms()
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

    def _harden_perms(self) -> None:
        """Restrict the capture DB (and its WAL/SHM siblings) to owner-only.

        Capture DBs hold full request/response bodies — session cookies, auth
        headers, credentials in transit. SQLite creates them with the process
        umask (commonly 0644), readable by every local account. This is
        idempotent: it also repairs DBs created before the hardening landed.
        Best-effort only — Windows and read-only mounts must not break capture.
        """
        import stat as _stat

        # The containing directory is the real boundary: at 0700 no other
        # local account can traverse into it, so the WAL/SHM siblings are
        # protected even before they exist (they are created on first write,
        # after this runs).
        # Only tighten the directory when it is the tool's own state dir. With
        # `--db /tmp/lab.db` this used to chmod /tmp to 0700, and with a bare
        # `--db proxy.db` it chmod'd whatever directory you happened to be in —
        # locking other accounts (or services) out of a shared path.
        parent = os.path.dirname(self.db_path) or "."
        try:
            if os.path.basename(os.path.abspath(parent)) == ".miniproxy":
                os.chmod(parent, 0o700)
        except OSError:
            pass
        for suffix in ("", "-wal", "-shm"):
            path = f"{self.db_path}{suffix}"
            try:
                if os.path.exists(path):
                    os.chmod(path, _stat.S_IRUSR | _stat.S_IWUSR)
            except OSError:
                continue

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

            CREATE TABLE IF NOT EXISTS noise_rules (
                id        INTEGER PRIMARY KEY AUTOINCREMENT,
                kind      TEXT NOT NULL DEFAULT 'host',
                value     TEXT NOT NULL,
                enabled   INTEGER NOT NULL DEFAULT 0,
                builtin   INTEGER NOT NULL DEFAULT 0,
                created   TEXT NOT NULL
            );
        CREATE UNIQUE INDEX IF NOT EXISTS idx_noise_rules_identity
                ON noise_rules (kind, value);

            CREATE TABLE IF NOT EXISTS repeater_tabs (
                id         INTEGER PRIMARY KEY AUTOINCREMENT,
                title      TEXT NOT NULL DEFAULT '',
                method     TEXT NOT NULL DEFAULT 'GET',
                url        TEXT NOT NULL DEFAULT '',
                headers    TEXT,
                body       TEXT,
                source_id  INTEGER,
                created    TEXT NOT NULL,
                updated    TEXT NOT NULL
            );

            CREATE TABLE IF NOT EXISTS repeater_history (
                id               INTEGER PRIMARY KEY AUTOINCREMENT,
                tab_id           INTEGER NOT NULL,
                created          TEXT NOT NULL,
                method           TEXT NOT NULL,
                url              TEXT NOT NULL,
                headers          TEXT,
                body             TEXT,
                status_code      INTEGER,
                response_headers TEXT,
                response_body    TEXT,
                error            TEXT,
                FOREIGN KEY (tab_id) REFERENCES repeater_tabs(id)
                  ON DELETE CASCADE
            );

            CREATE INDEX IF NOT EXISTS idx_repeater_history_tab
                ON repeater_history (tab_id, id DESC);

            CREATE TABLE IF NOT EXISTS rewrite_rules (
                id       INTEGER PRIMARY KEY AUTOINCREMENT,
                target   TEXT NOT NULL,
                kind     TEXT NOT NULL DEFAULT 'header',
                match    TEXT NOT NULL,
                replace  TEXT NOT NULL DEFAULT '',
                regex    INTEGER NOT NULL DEFAULT 0,
                enabled  INTEGER NOT NULL DEFAULT 1,
                created  TEXT NOT NULL
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
        # Row annotations: a highlight color and a free-text note, so a
        # finding can be marked and found again in a later session.
        for column, decl in (("highlight", "TEXT"), ("note", "TEXT")):
            try:
                conn.execute(f"ALTER TABLE requests ADD COLUMN {column} {decl}")
            except sqlite3.OperationalError as exc:
                if "duplicate column" not in str(exc).lower():
                    raise
        self._seed_noise_rules(conn)
        conn.execute(
            "INSERT OR IGNORE INTO config (key, value) VALUES ('intercept', '1')"
        )
        conn.commit()
        conn.close()

    @staticmethod
    def _seed_noise_rules(conn: sqlite3.Connection) -> None:
        """Seed the well-known telemetry/ad host list once, disabled.

        Seeded *disabled* on purpose: a built-in host list is a policy choice,
        not a fact about the target, so it must never silently drop captures.
        The user enables the rules they want (or opts into the bundle with one
        click in the dashboard / ``miniproxy noise enable --all``).
        """
        now = datetime.now(timezone.utc).isoformat()
        for host in DEFAULT_NOISE_HOSTS:
            conn.execute(
                "INSERT OR IGNORE INTO noise_rules (kind, value, enabled, builtin, created) "
                "VALUES ('host', ?, 0, 1, ?)",
                (host, now),
            )

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
            total_rows = int(conn.execute("SELECT COUNT(*) FROM requests").fetchone()[0])
            # One call may not delete more than a quarter of the table (at
            # least 100). A cap far below what the schema's own pages occupy
            # is unsatisfiable, and the loop used to keep going until nothing
            # was left.
            budget = max(100, total_rows // 4)
            removed_for_size = 0
            while page_size * page_count > self.max_db_bytes:
                if removed_for_size >= budget:
                    break
                ids = conn.execute("SELECT id FROM requests ORDER BY id LIMIT 100").fetchall()
                if not ids:
                    break
                conn.executemany("DELETE FROM intruder_results WHERE request_id=?", ids)
                conn.executemany("DELETE FROM requests WHERE id=?", ids)
                removed += len(ids)
                removed_for_size += len(ids)
                conn.commit()
                before = page_count
                try:
                    conn.execute("PRAGMA wal_checkpoint(TRUNCATE)")
                    conn.execute("VACUUM")
                except sqlite3.Error:
                    # Reclaiming disk space is best-effort; a reader holding
                    # the DB (TUI poll, dashboard) can legitimately block
                    # VACUUM.
                    pass
                page_count = int(conn.execute("PRAGMA page_count").fetchone()[0])
                if page_count >= before:
                    # No pages were reclaimed, so the size test above cannot
                    # become true. Without this the loop kept deleting 100
                    # rows per pass and emptied the database — deleting rows
                    # alone never shrinks page_count, only VACUUM does. Stop
                    # rather than destroy captures for no benefit; the row-count
                    # cap above is still enforced.
                    break
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

    # ── Filter compilation ────────────────────────────────────────────
    def _compile_filters(self, *, method: str = "", status_class: str = "",
                         url_substr: str = "", ids: str = "",
                         host: str = "", exclude_host: str = "",
                         hide_static: bool = False,
                         highlighted_only: bool = False,
                         body_substr: str = "", exclude_body: str = "",
                         min_length: int = 0,
                         ) -> tuple[list[str], list[Any]]:
        """Build the shared WHERE clause + params for every listing/count/export.

        One builder for all three paths so ``/api/logs``, ``/api/logs/count``
        and the HAR/JSON exports can never disagree about what "the current
        filters" selects — the bug that silently made counts disagree with
        exports.

        Filters:
        * ``method`` — exact, case-insensitive
        * ``status_class`` — ``2``..``5`` (HTTP class), ``0`` (transport
          error), ``pending`` (no response yet)
        * ``url_substr`` — case-insensitive substring over the full URL
        * ``ids`` — id selector: ``"42"``, ``"1,5,9"``, ``"100-200"`` or any
          comma/space separated mix (see :func:`parse_id_filter`)
        * ``host`` / ``exclude_host`` — host substring, case-insensitive.
          ``host`` narrows to one target (the noise killer); ``exclude_host``
          is how an explicit ignore-list is applied to an already-captured DB.
        * ``hide_static`` — drop images/fonts/css/js/media (see
          :func:`is_static_asset`). Applied in SQL so a huge DB stays bounded.
        * ``highlighted_only`` — only rows the user marked.
        * ``body_substr`` — case-insensitive substring of the request **or**
          response body. Body search is where "find the flag", "find the
          leaked token" and "which response mentions this param" actually get
          answered; a URL-only filter cannot see any of it.
        * ``exclude_body`` — the inverse: hide rows whose body contains this.
          Combined with ``body_substr`` it expresses "contains X but not Y".
        * ``min_length`` — minimum response body length, for finding the
          interesting fat response among a page's worth of thin ones.
        """
        clauses: list[str] = []
        params: list[Any] = []
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
        if host:
            h = str(host).lower()
            if "." in h:
                clauses.append(_HOST_SQL_DOMAIN)
                params.extend((h, h))
            else:
                clauses.append(_HOST_SQL_MATCH)
                params.append(h)
        if exclude_host:
            h = str(exclude_host).lower()
            if "." in h:
                clauses.append("NOT " + _HOST_SQL_DOMAIN)
                params.extend((h, h))
            else:
                clauses.append("NOT " + _HOST_SQL_MATCH)
                params.append(h)
        if hide_static:
            clauses.append("NOT " + _static_sql())
        if highlighted_only:
            clauses.append("(highlight IS NOT NULL AND TRIM(highlight) != '')")
        if body_substr:
            # Both sides of the exchange: a flag in a response and a payload
            # in a request are equally worth finding.
            clauses.append(
                "(INSTR(LOWER(COALESCE(response_body, '')), ?) > 0"
                " OR INSTR(LOWER(COALESCE(body, '')), ?) > 0)"
            )
            needle = body_substr.lower()
            params.extend([needle, needle])
        if exclude_body:
            clauses.append(
                "(INSTR(LOWER(COALESCE(response_body, '')), ?) = 0"
                " AND INSTR(LOWER(COALESCE(body, '')), ?) = 0)"
            )
            needle = exclude_body.lower()
            params.extend([needle, needle])
        if min_length and int(min_length) > 0:
            # Prefer the recorded original length (accurate even when the
            # stored body was truncated), fall back to what we kept.
            clauses.append(
                "(COALESCE(response_body_len, LENGTH(COALESCE(response_body, ''))) >= ?)"
            )
            params.append(int(min_length))
        id_parts = parse_id_filter(ids)
        if id_parts:
            # OR-ed inside one parenthesised group: `"1,5,9"` must match any of
            # them. Appending them as separate clauses would AND them together
            # and match nothing at all.
            clauses.append("(" + " OR ".join(c for c, _ in id_parts) + ")")
            for _, cparams in id_parts:
                params.extend(cparams)
        return clauses, params

    def get_logs(
        self,
        limit: int = 100,
        since_id: int = 0,
        *,
        method: str = "",
        status_class: str = "",
        url_substr: str = "",
        ids: str = "",
        host: str = "",
        exclude_host: str = "",
        hide_static: bool = False,
        highlighted_only: bool = False,
        body_substr: str = "",
        exclude_body: str = "",
        min_length: int = 0,
    ) -> list[dict[str, Any]]:
        """Newest-first capture listing with server-side filtering.

        See :meth:`_compile_filters` for the full filter list. ``since_id``
        is the cheap incremental-poll cursor and is always applied first.
        """
        clauses, params = self._compile_filters(
            method=method, status_class=status_class, url_substr=url_substr,
            ids=ids, host=host, exclude_host=exclude_host,
            hide_static=hide_static, highlighted_only=highlighted_only,
            body_substr=body_substr, exclude_body=exclude_body,
            min_length=min_length,
        )
        # since_id is a range bound, not a filter, so it goes in front.
        clauses.insert(0, "id > ?")
        params.insert(0, since_id)
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
        """Total rows matching the filters.

        Runs a real ``COUNT(*)`` rather than counting a materialised list:
        the previous implementation called ``get_logs(limit=10_000_000)``,
        which loaded every matching row into Python just to take ``len()`` —
        hundreds of MB on a large capture DB.
        """
        if not filters:
            conn = self._connect()
            total = conn.execute("SELECT COUNT(*) FROM requests").fetchone()[0]
            conn.close()
            return int(total)
        clauses, params = self._compile_filters(**filters)
        where = ("WHERE " + " AND ".join(clauses)) if clauses else ""
        conn = self._connect()
        total = conn.execute(f"SELECT COUNT(*) FROM requests {where}", params).fetchone()[0]
        conn.close()
        return int(total)

    def list_hosts(self, limit: int = 200) -> list[dict[str, Any]]:
        """Distinct hosts with capture counts, busiest first.

        Computed in Python because SQLite has no URL-parsing function: host
        extraction is ``substr(url, instr(url,'://')+3)`` up to the first
        ``/``. The candidate set is collapsed per host first so the parse runs
        once per distinct host rather than once per row.
        """
        conn = self._connect()
        rows = conn.execute(
            "SELECT url, content_type FROM requests ORDER BY id DESC LIMIT 20000"
        ).fetchall()
        conn.close()
        stats: dict[str, dict[str, Any]] = {}
        for r in rows:
            url = r["url"] or ""
            host = host_of(url) or "(unknown)"
            entry = stats.get(host)
            if entry is None:
                entry = stats[host] = {"host": host, "count": 0, "static": 0, "latest_id": 0}
            entry["count"] += 1
            if is_static_asset(url, r["content_type"] or ""):
                entry["static"] += 1
        out = sorted(stats.values(), key=lambda h: -h["count"])
        return out[: max(int(limit), 1)]

    def get_request(self, req_id: int) -> dict[str, Any] | None:
        conn = self._connect()
        row = conn.execute(
            "SELECT * FROM requests WHERE id=?", (req_id,)
        ).fetchone()
        conn.close()
        return dict(row) if row else None

    # ── Row annotations (highlight color + note) ────────────────────

    def set_highlight(self, req_id: int, color: str | None) -> bool:
        """Paint (or clear) a capture's row highlight.

        Rejects colors outside :data:`HIGHLIGHT_COLORS` rather than storing
        arbitrary CSS: the value is echoed into a ``style`` attribute by the
        dashboard, so an unvalidated string would be a stored-XSS vector.
        """
        if not is_valid_highlight(color):
            raise ValueError(f"invalid highlight color: {color!r}")
        conn = self._connect()
        cur = conn.execute(
            "UPDATE requests SET highlight=? WHERE id=?", (color or None, int(req_id))
        )
        conn.commit()
        conn.close()
        return bool(cur.rowcount)

    def set_note(self, req_id: int, note: str) -> bool:
        """Attach (or clear, with an empty string) a free-text note."""
        conn = self._connect()
        cur = conn.execute(
            "UPDATE requests SET note=? WHERE id=?",
            ((note or "")[:4000] or None, int(req_id)),
        )
        conn.commit()
        conn.close()
        return bool(cur.rowcount)

    def annotate(self, req_id: int, *, highlight: str | None = None,
                 note: str | None = None) -> bool:
        """Set whichever annotation keys were supplied (absent keys untouched)."""
        sets: list[str] = []
        params: list[Any] = []
        if highlight is not None:
            if not is_valid_highlight(highlight):
                raise ValueError(f"invalid highlight color: {highlight!r}")
            sets.append("highlight=?")
            params.append(highlight or None)
        if note is not None:
            sets.append("note=?")
            params.append((note or "")[:4000] or None)
        if not sets:
            return self.get_request(req_id) is not None
        params.append(int(req_id))
        conn = self._connect()
        cur = conn.execute(f"UPDATE requests SET {', '.join(sets)} WHERE id=?", params)
        conn.commit()
        conn.close()
        return bool(cur.rowcount)

    def get_highlights(self) -> dict[int, str]:
        """Map of id → highlight color for every annotated capture."""
        conn = self._connect()
        rows = conn.execute(
            "SELECT id, highlight FROM requests "
            "WHERE highlight IS NOT NULL AND TRIM(highlight) != ''"
        ).fetchall()
        conn.close()
        return {int(r["id"]): str(r["highlight"]) for r in rows}

    # ── Repeater tabs + per-tab history ──────────────────────────────

    def create_repeater_tab(self, *, title: str = "", method: str = "GET",
                            url: str = "", headers: dict | None = None,
                            body: str = "", source_id: int | None = None) -> dict:
        """Create a repeater tab and return it.

        Tabs are persisted rather than held in the browser so a refresh (or a
        different device — the dashboard is often driven from a phone) does not
        lose work in progress.
        """
        now = datetime.now(timezone.utc).isoformat()
        label = (title or url or "New tab").strip()[:120]
        conn = self._connect()
        cur = conn.execute(
            "INSERT INTO repeater_tabs (title, method, url, headers, body,"
            " source_id, created, updated) VALUES (?,?,?,?,?,?,?,?)",
            (label, (method or "GET").upper()[:16], url[:4000],
             json.dumps(headers or {}), body or "", source_id, now, now),
        )
        conn.commit()
        tab_id = cur.lastrowid
        conn.close()
        return self.get_repeater_tab(tab_id) or {}

    def get_repeater_tabs(self) -> list[dict[str, Any]]:
        """All tabs, most recently updated first."""
        conn = self._connect()
        rows = conn.execute(
            "SELECT * FROM repeater_tabs ORDER BY updated DESC, id DESC"
        ).fetchall()
        conn.close()
        return [self._tab_row(r) for r in rows]

    def get_repeater_tab(self, tab_id: int) -> dict[str, Any] | None:
        conn = self._connect()
        row = conn.execute(
            "SELECT * FROM repeater_tabs WHERE id=?", (int(tab_id),)
        ).fetchone()
        conn.close()
        return self._tab_row(row) if row else None

    @staticmethod
    def _tab_row(row) -> dict[str, Any]:
        out = dict(row)
        raw = out.get("headers")
        if isinstance(raw, str):
            try:
                out["headers"] = json.loads(raw or "{}")
            except ValueError:
                out["headers"] = {}
        return out

    def update_repeater_tab(self, tab_id: int, **fields: Any) -> bool:
        """Update a tab. Only whitelisted columns are writable."""
        allowed = {"title", "method", "url", "headers", "body", "source_id"}
        sets, params = [], []
        for key, value in fields.items():
            if key not in allowed:
                raise ValueError(f"unknown tab field: {key}")
            if key == "headers":
                sets.append("headers=?")
                params.append(json.dumps(value or {}))
            elif key == "method":
                sets.append("method=?")
                params.append(str(value or "GET").upper()[:16])
            elif key == "title":
                sets.append("title=?")
                params.append(str(value or "")[:120])
            elif key == "url":
                sets.append("url=?")
                params.append(str(value or "")[:4000])
            elif key == "body":
                sets.append("body=?")
                params.append(str(value or "")[:100_000])
            else:
                sets.append("source_id=?")
                params.append(value)
        if not sets:
            return self.get_repeater_tab(tab_id) is not None
        sets.append("updated=?")
        params.extend([datetime.now(timezone.utc).isoformat(), int(tab_id)])
        conn = self._connect()
        cur = conn.execute(
            f"UPDATE repeater_tabs SET {', '.join(sets)} WHERE id=?", params
        )
        conn.commit()
        conn.close()
        return bool(cur.rowcount)

    def delete_repeater_tab(self, tab_id: int) -> bool:
        conn = self._connect()
        # Explicit child delete: FK cascades are off unless the pragma is set
        # on *this* connection, and orphan history would be invisible garbage.
        conn.execute("DELETE FROM repeater_history WHERE tab_id=?", (int(tab_id),))
        cur = conn.execute("DELETE FROM repeater_tabs WHERE id=?", (int(tab_id),))
        conn.commit()
        conn.close()
        return bool(cur.rowcount)

    def add_repeater_history(self, tab_id: int, *, method: str, url: str,
                             headers: dict | None = None, body: str = "",
                             status_code: int | None = None,
                             response_headers: dict | None = None,
                             response_body: str = "", error: str | None = None,
                             ) -> int | None:
        """Record one send. Returns the history id, or None if the tab is gone."""
        conn = self._connect()
        if not conn.execute(
            "SELECT 1 FROM repeater_tabs WHERE id=?", (int(tab_id),)
        ).fetchone():
            conn.close()
            return None
        cur = conn.execute(
            "INSERT INTO repeater_history (tab_id, created, method, url,"
            " headers, body, status_code, response_headers, response_body,"
            " error) VALUES (?,?,?,?,?,?,?,?,?,?)",
            (int(tab_id), datetime.now(timezone.utc).isoformat(),
             (method or "GET").upper()[:16], str(url or "")[:4000],
             json.dumps(headers or {}), str(body or "")[:100_000],
             status_code, json.dumps(response_headers or {}),
             str(response_body or "")[:100_000], (error or "")[:500] or None),
        )
        conn.commit()
        rid = cur.lastrowid
        conn.close()
        self._trim_history(int(tab_id))
        return rid

    HISTORY_LIMIT = 50

    def _trim_history(self, tab_id: int) -> None:
        """Keep the last N sends per tab — history is a comparison aid, not
        an archive, and an unbounded table would grow with every fuzz."""
        conn = self._connect()
        conn.execute(
            "DELETE FROM repeater_history WHERE tab_id=? AND id NOT IN "
            "(SELECT id FROM repeater_history WHERE tab_id=? ORDER BY id DESC LIMIT ?)",
            (int(tab_id), int(tab_id), self.HISTORY_LIMIT),
        )
        conn.commit()
        conn.close()

    def get_repeater_history(self, tab_id: int,
                             limit: int = 50) -> list[dict[str, Any]]:
        """Newest-first send history for a tab."""
        conn = self._connect()
        rows = conn.execute(
            "SELECT * FROM repeater_history WHERE tab_id=? "
            "ORDER BY id DESC LIMIT ?",
            (int(tab_id), max(int(limit), 1)),
        ).fetchall()
        conn.close()
        out = []
        for r in rows:
            d = dict(r)
            for key in ("headers", "response_headers"):
                if isinstance(d.get(key), str):
                    try:
                        d[key] = json.loads(d[key] or "{}")
                    except ValueError:
                        d[key] = {}
            out.append(d)
        return out

    # ── Match & replace rules ────────────────────────────────────────

    REWRITE_TARGETS = ("header", "query", "body")
    REWRITE_KINDS = ("exact", "contains", "regex")

    def add_rewrite_rule(self, *, target: str, kind: str, match: str,
                         replace: str = "", regex: bool = False,
                         enabled: bool = True) -> int:
        """Add a rewrite rule applied to in-flight traffic.

        ``kind`` must agree with ``regex``: a regex flag on an ``exact`` match
        would silently do nothing, which is worse than refusing.
        """
        target = str(target or "").strip().lower()
        kind = str(kind or "exact").strip().lower()
        if target not in self.REWRITE_TARGETS:
            raise ValueError(f"invalid rewrite target: {target!r}")
        if kind not in self.REWRITE_KINDS:
            raise ValueError(f"invalid rewrite kind: {kind!r}")
        needle = str(match or "")
        if not needle:
            raise ValueError("rewrite rule needs a match value")
        if kind == "regex":
            try:
                re.compile(needle)
            except re.error as exc:
                raise ValueError(f"invalid regex: {exc}") from exc
        elif regex:
            raise ValueError("regex=True requires kind='regex'")
        conn = self._connect()
        cur = conn.execute(
            "INSERT INTO rewrite_rules (target, kind, match, replace, regex,"
            " enabled, created) VALUES (?,?,?,?,?,?,?)",
            (target, kind, needle, str(replace or "")[:2000],
             1 if kind == "regex" else 0, 1 if enabled else 0,
             datetime.now(timezone.utc).isoformat()),
        )
        conn.commit()
        rid = cur.lastrowid
        conn.close()
        return int(rid)

    def get_rewrite_rules(self, enabled_only: bool = False) -> list[dict[str, Any]]:
        conn = self._connect()
        sql = "SELECT * FROM rewrite_rules"
        if enabled_only:
            sql += " WHERE enabled=1"
        sql += " ORDER BY id"
        rows = conn.execute(sql).fetchall()
        conn.close()
        return [dict(r) for r in rows]

    def set_rewrite_rule_enabled(self, rule_id: int, enabled: bool) -> bool:
        conn = self._connect()
        cur = conn.execute(
            "UPDATE rewrite_rules SET enabled=? WHERE id=?",
            (1 if enabled else 0, int(rule_id)),
        )
        conn.commit()
        conn.close()
        return bool(cur.rowcount)

    def delete_rewrite_rule(self, rule_id: int) -> bool:
        conn = self._connect()
        cur = conn.execute("DELETE FROM rewrite_rules WHERE id=?", (int(rule_id),))
        conn.commit()
        conn.close()
        return bool(cur.rowcount)

    # ── Noise rules ────────────────────────────────────────────────

    def list_noise_rules(self) -> list[dict[str, Any]]:
        """All noise rules, enabled first then alphabetical."""
        conn = self._connect()
        rows = conn.execute(
            "SELECT * FROM noise_rules ORDER BY enabled DESC, kind, value"
        ).fetchall()
        conn.close()
        return [dict(r) for r in rows]

    def add_noise_rule(self, value: str, kind: str = "host",
                       enabled: bool = True) -> int:
        """Add a noise rule (idempotent on ``(kind, value)``).

        A ``host`` rule may be given as a bare host or a ``*.suffix`` wildcard;
        both are stored lowercased and matched as substrings of the URL's host
        part, so ``*.mozilla.org`` also covers subdomains.
        """
        kind = (kind or "host").strip().lower()
        if kind not in ("host", "content_type"):
            raise ValueError(f"invalid noise rule kind: {kind!r}")
        val = (value or "").strip().lower()
        if not val:
            raise ValueError("noise rule value is empty")
        if kind == "host" and "/" in val:
            raise ValueError("noise host rules take a host, not a URL path")
        conn = self._connect()
        cur = conn.execute(
            "INSERT INTO noise_rules (kind, value, enabled, builtin, created) "
            "VALUES (?, ?, ?, 0, ?) ON CONFLICT(kind, value) DO UPDATE SET "
            "enabled=excluded.enabled",
            (kind, val, 1 if enabled else 0,
             datetime.now(timezone.utc).isoformat()),
        )
        if not cur.lastrowid:
            row = conn.execute(
                "SELECT id FROM noise_rules WHERE kind=? AND value=?", (kind, val)
            ).fetchone()
        conn.commit()
        conn.close()
        return int(cur.lastrowid or row["id"])

    def set_noise_rule_enabled(self, rule_id: int, enabled: bool) -> bool:
        conn = self._connect()
        cur = conn.execute(
            "UPDATE noise_rules SET enabled=? WHERE id=?",
            (1 if enabled else 0, int(rule_id)),
        )
        conn.commit()
        conn.close()
        return bool(cur.rowcount)

    def enable_all_noise_rules(self, enabled: bool = True) -> int:
        """Flip the **bundled** rules at once (the 'opt into the built-in
        list' action).

        Scoped to ``builtin`` rows. This used to flip *every* rule, so a
        deliberate "this host stays" rule of your own was silently re-enabled
        the moment you opted into the bundled list — and the button says
        bundled, and the UI cannot show you what a bundled row is once it has
        been renamed.
        """
        conn = self._connect()
        cur = conn.execute(
            "UPDATE noise_rules SET enabled=? WHERE builtin=1", (1 if enabled else 0,)
        )
        conn.commit()
        conn.close()
        return max(cur.rowcount, 0)

    def delete_noise_rule(self, rule_id: int) -> bool:
        conn = self._connect()
        cur = conn.execute("DELETE FROM noise_rules WHERE id=?", (int(rule_id),))
        conn.commit()
        conn.close()
        return bool(cur.rowcount)

    def active_noise_rules(self) -> list[str]:
        """Enabled host rules as matcher patterns (lowercased)."""
        conn = self._connect()
        rows = conn.execute(
            "SELECT value FROM noise_rules WHERE enabled=1 AND kind='host'"
        ).fetchall()
        conn.close()
        return [str(r["value"]).lower() for r in rows]

    @staticmethod
    def _matches_rule(host: str, pattern: str) -> bool:
        """Host rule match: exact host, suffix (``.evil.com``) or subdomain
        wildcard (``*.evil.com``) — all case-insensitive."""
        host = (host or "").lower()
        pattern = (pattern or "").lower().lstrip("*").lstrip(".")
        if not pattern:
            return False
        return host == pattern or host.endswith("." + pattern)

    def is_noise(self, url: str, content_type: str = "") -> bool:
        """Capture-time gate: should this flow be dropped before it is stored?

        True when the URL's host matches an enabled host rule. Static-asset
        detection is *not* applied here by default — dropping an asset can
        hide an application-logic asset, and this returns before the response
        is known, so ``content_type`` is empty at request time.
        """
        host = host_of(url)
        if not host:
            return False
        return any(self._matches_rule(host, p) for p in self.active_noise_rules())

    def scan_noise(self, *, ids: str = "",
                   keep_hosts: list[str] | None = None) -> dict[str, Any]:
        """Dry run for :meth:`clean_noise` — what would be removed, and why.

        Returns a preview (never deletes) so the UI can show the blast radius
        before the user commits, plus the survivors so the effect is obvious.

        ``keep_hosts`` must be the same list passed to :meth:`clean_noise`, or
        the preview over-reports: the CLI showed "This would delete N" without
        the ``--keep-host`` exclusions and then deleted fewer.
        """
        rules = self.active_noise_rules()
        keep_set = [str(h).lower() for h in (keep_hosts or []) if str(h).strip()]
        conn = self._connect()
        rows = conn.execute(
            "SELECT id, url, content_type FROM requests ORDER BY id DESC"
        ).fetchall()
        conn.close()
        by_host: dict[str, int] = {}
        matched: list[dict[str, Any]] = []
        keep = 0
        for r in rows:
            host = host_of(r["url"] or "") or "(unknown)"
            if any(self._matches_rule(host, k) for k in keep_set):
                keep += 1
                continue
            entry = by_host.get(host)
            static = is_static_asset(r["url"] or "", r["content_type"] or "")
            if static:
                entry = entry if entry is not None else by_host.setdefault(
                    host, 0)
                by_host[host] = entry + 1
                matched.append({"id": int(r["id"]), "host": host,
                                "reason": "static asset"})
            elif rules and any(self._matches_rule(host, p) for p in rules):
                if host not in by_host:
                    by_host[host] = 0
                by_host[host] += 1
                matched.append({"id": int(r["id"]), "host": host,
                                "reason": "noise host"})
            else:
                keep += 1
        matched.sort(key=lambda m: -m["id"])
        return {
            "rules": rules,
            "matched": len(matched),
            "keep": keep,
            "by_host": [{"host": h, "removed": n}
                        for h, n in sorted(by_host.items(), key=lambda kv: -kv[1])
                        if n],
            "sample": matched[:200],
        }

    def clean_noise(self, *, keep_hosts: list[str] | None = None,
                    backup: bool = True) -> dict[str, Any]:
        """Delete noise captures and intruder results that depend on them.

        With ``backup=True`` (the default) the DB is copied to
        ``<path>.noise-backup-<n>.db`` first, so an over-eager rule set is
        always recoverable. Returns the backup path and the removal breakdown.
        """
        preview = self.scan_noise()
        backup_path = ""
        if backup and preview["matched"]:
            backup_path = self._backup_db()
            if not backup_path:
                # The UI and CLI both promise a timestamped backup before
                # anything is deleted ("so this is reversible"). Proceeding
                # after a failed backup silently breaks that promise, and the
                # deletion is exactly the irreversible part.
                raise NoiseBackupError(
                    "could not write the safety backup, so nothing was "
                    "deleted. Check free space and permissions on the "
                    "database's directory, or call again with backup disabled "
                    "if you accept the risk."
                )
        keep = [str(h).lower() for h in (keep_hosts or []) if str(h).strip()]
        ids: list[int] = []
        conn = self._connect()
        try:
            rows = conn.execute("SELECT id, url, content_type FROM requests").fetchall()
            rules = preview["rules"]
            for r in rows:
                host = host_of(r["url"] or "") or "(unknown)"
                if any(self._matches_rule(host, k) for k in keep):
                    continue
                static = is_static_asset(r["url"] or "", r["content_type"] or "")
                noisy = static or (rules and any(self._matches_rule(host, p) for p in rules))
                if noisy:
                    ids.append(int(r["id"]))
            if ids:
                conn.executemany(
                    "DELETE FROM intruder_results WHERE request_id=?",
                    [(i,) for i in ids],
                )
                conn.executemany("DELETE FROM requests WHERE id=?", [(i,) for i in ids])
                conn.commit()
                try:
                    conn.execute("PRAGMA wal_checkpoint(TRUNCATE)")
                except sqlite3.Error:
                    pass
        finally:
            conn.close()
        return {"removed": len(ids), "backup": backup_path,
                "kept_hosts": keep, "by_host": preview["by_host"]}

    def _backup_db(self) -> str:
        """Copy the capture DB next to itself; returns the new path ('' on failure)."""
        import shutil

        src = Path(self.db_path)
        if not src.is_file():
            return ""
        stamp = datetime.now(timezone.utc).strftime("%Y%m%d-%H%M%S")
        dest = src.with_name(f"{src.name}.noise-backup-{stamp}.db")
        try:
            # sqlite3 backup API, not shutil: shutil can copy a torn file when
            # the proxy is mid-write. WAL siblings are checkpointed into the
            # destination so the copy is self-contained.
            src_conn = sqlite3.connect(src)
            try:
                dst_conn = sqlite3.connect(dest)
                try:
                    src_conn.backup(dst_conn)
                finally:
                    dst_conn.close()
            finally:
                src_conn.close()
            return str(dest)
        except sqlite3.Error:
            dest.unlink(missing_ok=True)
            return ""

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

    def store_intruder_results(self, results: list[dict[str, Any]]) -> list[dict[str, Any]]:
        """Persist Intruder results, stamping each dict with its new row id.

        The ids are attached **in place** on the dicts passed in, because the
        caller hands the same list object to the client. The Intruder's own
        results table has an id space separate from captures, so the dashboard
        needs those ids to diff two of its results against each other.
        """
        conn = self._connect()
        now = datetime.now(timezone.utc).isoformat()
        for r in results:
            try:
                cur = conn.execute(
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
                r["id"] = cur.lastrowid
            except sqlite3.Error:
                # FK violation (capture pruned mid-attack) or a malformed
                # row must not lose the whole batch — skip and continue.
                continue
        conn.commit()
        conn.close()
        return results

    def get_intruder_results(self, request_id: int) -> list[dict[str, Any]]:
        conn = self._connect()
        rows = conn.execute(
            "SELECT * FROM intruder_results WHERE request_id=? ORDER BY id",
            (request_id,),
        ).fetchall()
        conn.close()
        return [dict(r) for r in rows]

    def get_intruder_result(self, result_id: int) -> dict[str, Any] | None:
        """One Intruder result by its own id.

        ``intruder_results`` has an id space separate from the capture table,
        so the Diff tab needs its own lookup to reach these rows.
        """
        conn = self._connect()
        row = conn.execute(
            "SELECT * FROM intruder_results WHERE id=?", (result_id,)
        ).fetchone()
        conn.close()
        return dict(row) if row is not None else None

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

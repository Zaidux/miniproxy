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


def _static_sql() -> str:
    """SQL twin of :func:`is_static_asset`, used by the ``hide_static`` filter.

    Mirrors the three-way resolution exactly: a known asset MIME matches, a
    known non-asset MIME does not, and only an absent type falls back to the
    URL extension. ``content_type IS NULL OR = ''`` covers pending flows and
    304s, which are the rows with no type recorded.

    Asserted in lockstep with the Python version by
    ``test_sql_hide_static_matches_python``.
    """
    asset_mimes = " OR ".join(
        f"LOWER(content_type) LIKE '{p}%'" for p in sorted(STATIC_CONTENT_TYPES)
    )
    exts = " OR ".join(
        f"LOWER(url) LIKE '%.{e}'" for e in sorted(STATIC_EXTENSIONS)
    )
    return (
        "(" + asset_mimes + ")"
        " OR ((content_type IS NULL OR TRIM(content_type) = '')"
        " AND (" + exts + "))"
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
        try:
            os.chmod(os.path.dirname(self.db_path) or ".", 0o700)
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

    # ── Filter compilation ────────────────────────────────────────────
    def _compile_filters(self, *, method: str = "", status_class: str = "",
                         url_substr: str = "", ids: str = "",
                         host: str = "", exclude_host: str = "",
                         hide_static: bool = False,
                         highlighted_only: bool = False) -> tuple[list[str], list[Any]]:
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
            clauses.append(_HOST_SQL_MATCH)
            params.append(str(host).lower())
        if exclude_host:
            clauses.append("NOT " + _HOST_SQL_MATCH)
            params.append(str(exclude_host).lower())
        if hide_static:
            clauses.append("NOT " + _static_sql())
        if highlighted_only:
            clauses.append("(highlight IS NOT NULL AND TRIM(highlight) != '')")
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
    ) -> list[dict[str, Any]]:
        """Newest-first capture listing with server-side filtering.

        See :meth:`_compile_filters` for the full filter list. ``since_id``
        is the cheap incremental-poll cursor and is always applied first.
        """
        clauses, params = self._compile_filters(
            method=method, status_class=status_class, url_substr=url_substr,
            ids=ids, host=host, exclude_host=exclude_host,
            hide_static=hide_static, highlighted_only=highlighted_only,
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
        """Flip every rule at once (the 'opt into the built-in list' action)."""
        conn = self._connect()
        cur = conn.execute(
            "UPDATE noise_rules SET enabled=?", (1 if enabled else 0,)
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

    def scan_noise(self, *, ids: str = "") -> dict[str, Any]:
        """Dry run for :meth:`clean_noise` — what would be removed, and why.

        Returns a preview (never deletes) so the UI can show the blast radius
        before the user commits, plus the survivors so the effect is obvious.
        """
        rules = self.active_noise_rules()
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

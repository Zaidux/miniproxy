"""Versioned local contracts for CLI consumers; no dashboard is required."""
from __future__ import annotations

import hashlib
import sqlite3
from pathlib import Path
from importlib.resources import files
from typing import Any
from urllib.parse import parse_qsl, urlsplit, urlunsplit

SCHEMA_VERSION = 1


def open_evidence(path: str):
    """Read-only DB adapter: never creates/migrates a missing capture."""
    from miniproxy.addon.db import Database
    class EvidenceDatabase(Database):
        def __init__(self, selected):
            self.db_path = str(Path(selected).expanduser().resolve())
            if not Path(self.db_path).is_file():
                raise FileNotFoundError("Capture database does not exist")
            connection = self._connect()
            try:
                connection.execute("SELECT id, url, method, response_code FROM requests LIMIT 1").fetchall()
            finally:
                connection.close()

        def _connect(self):
            connection = sqlite3.connect(Path(self.db_path).as_uri() + "?mode=ro", uri=True, timeout=0.5)
            connection.row_factory = sqlite3.Row
            return connection
    return EvidenceDatabase(path)


def addon_manifest() -> dict[str, Any]:
    from miniproxy import __version__
    resources = {name: hashlib.sha256((files("miniproxy.addon") / name).read_bytes()).hexdigest()
                 for name in ("proxy.py", "db.py", "intercept_addon.py")}
    dependencies = {name: hashlib.sha256((files("miniproxy") / name).read_bytes()).hexdigest()
                    for name in ("scope.py", "runtime.py")}
    return {"schema_version": SCHEMA_VERSION, "package": "riciplay-miniproxy",
            "package_version": __version__, "hash_algorithm": "sha256",
            "resources": resources, "package_dependencies": dependencies}


def capabilities() -> dict[str, Any]:
    from miniproxy import __version__
    return {"schema_version": SCHEMA_VERSION, "package_version": __version__,
            "capabilities": {"json_status": True, "local_health": True,
                             "cursor_query": True, "addon_manifest": True,
                             "jsonl_export": True, "endpoint_inventory": True,
                             "upstream_reachability_probe": False}}


def query(db, *, limit: int = 100, before_id: int | None = None,
          since_id: int = 0, **filters) -> dict[str, Any]:
    """Stable descending ID cursor; filters apply in SQL before LIMIT.

    ``since_id`` is an exclusive lower bound; ``before_id`` an exclusive upper
    bound. Counts cover the matching DB view, not just a prefetched window.
    """
    if isinstance(limit, bool) or not isinstance(limit, int) or not 1 <= limit <= 5000:
        raise ValueError("limit must be in 1..5000")
    for value in (before_id, since_id):
        if value is not None and (isinstance(value, bool) or not isinstance(value, int) or value < 0):
            raise ValueError("ID cursor must be a nonnegative integer")
    clauses, params = db._compile_filters(**filters)
    clauses.append("id > ?")
    params.append(since_id)
    if before_id is not None:
        clauses.append("id < ?")
        params.append(before_id)
    where = " AND ".join(clauses)
    connection = db._connect()
    try:
        # One read transaction pins counts/items while new capture arrives.
        connection.execute("BEGIN")
        matched = int(connection.execute(f"SELECT COUNT(*) FROM requests WHERE {where}", params).fetchone()[0])
        total = int(connection.execute("SELECT COUNT(*) FROM requests").fetchone()[0])
        rows = connection.execute(
            f"SELECT *, (response_code IS NOT NULL) AS has_response FROM requests WHERE {where} ORDER BY id DESC LIMIT ?",
            (*params, limit + 1)).fetchall()
        items = [dict(row) for row in rows[:limit]]
    finally:
        connection.close()
    more = len(rows) > limit
    return {"schema_version": SCHEMA_VERSION, "items": items, "count": len(items),
            "matched_count": matched, "total_captured": total, "has_more": more,
            "next_cursor": items[-1]["id"] if more and items else None,
            "since_id": since_id, "before_id": before_id, "limit": limit,
            "coverage": "matching_rows_in_read_transaction", "filters": filters}


def endpoint_inventory(db, *, limit: int = 5000, **filters) -> dict[str, Any]:
    """Bounded endpoint aggregation with explicit coverage and blank parameters."""
    page = query(db, limit=limit, **filters)
    endpoints: dict[tuple[str, str], dict[str, Any]] = {}
    for row in page["items"]:
        try:
            parsed = urlsplit(row.get("url") or "")
        except ValueError:
            continue
        method = str(row.get("method") or "GET").upper()
        base = urlunsplit((parsed.scheme, parsed.netloc, parsed.path, "", ""))
        key = (method, base)
        names = {name for name, _ in parse_qsl(parsed.query, keep_blank_values=True)}
        item = endpoints.setdefault(key, {"method": method, "url": base, "host": parsed.netloc,
                                         "path": parsed.path, "query_params": [], "hits": 0, "example_flow_ids": []})
        item["query_params"] = sorted(set(item["query_params"]) | names)
        item["hits"] += 1
        if len(item["example_flow_ids"]) < 3:
            item["example_flow_ids"].append(row["id"])
    return {"schema_version": SCHEMA_VERSION, "endpoints": sorted(endpoints.values(), key=lambda x: -x["hits"]),
            "rows_examined": page["count"], "matched_count": page["matched_count"],
            "complete": not page["has_more"], "next_cursor": page["next_cursor"],
            "coverage": "hits_and_parameters_are_for_this_bounded_capture_window", "filters": filters}

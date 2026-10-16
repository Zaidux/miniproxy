"""Response diffing — compare two captures the way Burp's Compare does.

The use case this exists for is access-control/IDOR testing: send the same
request twice with one parameter changed and see *what actually changed*.
Eyeballing two hex dumps does not scale, and a character-level diff of two
HTML pages is useless because one shifted attribute re-aligns every
subsequent byte.

Three granularities, because they answer different questions:

* ``token``  — word-level. "Is this token new?" Best for HTML/text/JSON.
* ``char``   — character-level with context. Best for short payloads, and for
  spotting exactly which byte of a token moved.
* ``json``   — structural, keyed by JSON path. "Which field changed?" This is
  the one that answers "did ``role`` go from ``user`` to ``admin``?" without
  reading either body.

The module is pure (no DB, no Flask) so it can be tested directly and reused
by the CLI and the TUI.
"""
from __future__ import annotations

import json
import re
from typing import Any

MAX_TOKENS = 4000

# Markup and separator characters, kept as their own tokens so a diff of
# minified HTML still localises the change instead of reporting one blob.
_TOKEN_SPLIT = re.compile(r"[\s<>()\[\]{}\"',;=&|]+")


def _flatten_json(obj: Any, prefix: str = "") -> dict[str, str]:
    """Flatten nested JSON to ``{"a.b.0": "value"}`` for path-wise diffing."""
    out: dict[str, str] = {}
    if isinstance(obj, dict):
        for k, v in obj.items():
            path = f"{prefix}.{k}" if prefix else str(k)
            if isinstance(v, (dict, list)):
                out.update(_flatten_json(v, path))
            else:
                out[path] = v if isinstance(v, str) else json.dumps(v)
    elif isinstance(obj, list):
        for i, v in enumerate(obj):
            path = f"{prefix}.{i}"
            if isinstance(v, (dict, list)):
                out.update(_flatten_json(v, path))
            else:
                out[path] = v if isinstance(v, str) else json.dumps(v)
    else:
        out[prefix or "$"] = obj if isinstance(obj, str) else json.dumps(obj)
    return out


def _try_json(text: str) -> dict[str, str] | None:
    if not text or not text.strip():
        return None
    try:
        return _flatten_json(json.loads(text))
    except (ValueError, TypeError):
        return None


def diff_status(a_code: Any, b_code: Any) -> str:
    """Coarse outcome banner: same / different."""
    return "same" if str(a_code) == str(b_code) else "different"


def diff_json(a_text: str, b_text: str) -> dict[str, Any]:
    """Structural JSON diff keyed by dotted path."""
    fa, fb = _try_json(a_text), _try_json(b_text)
    if fa is None or fb is None:
        return {"applicable": False}
    changed, added, removed = [], [], []
    for path in sorted(set(fa) | set(fb)):
        va, vb = fa.get(path), fb.get(path)
        if va == vb:
            continue
        entry = {"path": path, "a": va, "b": vb}
        if path not in fb:
            removed.append(entry)
        elif path not in fa:
            added.append(entry)
        else:
            changed.append(entry)
    return {
        "applicable": True,
        "changed": changed,
        "added": added,
        "removed": removed,
        "identical": not (changed or added or removed),
        "total_paths": len(set(fa) | set(fb)),
    }


def diff_char(a_text: str, b_text: str, context: int = 40) -> dict[str, Any]:
    """Character-level diff of the changed region, with context either side."""
    a, b = str(a_text or ""), str(b_text or "")
    # Common prefix/suffix trim: almost every "difference" is a short insertion
    # or a substitution in the middle of an otherwise identical body, so
    # trimming first avoids diffing hundreds of identical bytes.
    i = 0
    while i < len(a) and i < len(b) and a[i] == b[i]:
        i += 1
    j = 0
    while j < len(a) - i and j < len(b) - i and a[len(a) - 1 - j] == b[len(b) - 1 - j]:
        j += 1
    a_mid, b_mid = a[i:len(a) - j], b[i:len(b) - j]
    start = max(0, i - context)
    return {
        "applicable": True,
        "identical": not a_mid and not b_mid,
        "offset": i,
        "a_before": a[start:i],
        "a_mid": a_mid,
        "b_before": b[start:i],
        "b_mid": b_mid,
        "a_after": a[len(a) - j:len(a) - j + context],
        "b_after": b[len(b) - j:len(b) - j + context],
        "len_a": len(a),
        "len_b": len(b),
    }


def _tokenize(text: str) -> list[str]:
    """Split into comparison tokens.

    Splitting on whitespace alone is not enough: a minified HTML body like
    ``<p>role=user</p>`` is a *single* whitespace token, so a word-level diff
    would report the entire body as changed and tell you nothing. Markup and
    separator characters are therefore treated as token boundaries too, which
    makes the diff useful on real HTML, form-encoded and JSON-ish payloads.
    """
    return [t for t in _TOKEN_SPLIT.split(str(text or "")) if t]


def diff_token(a_text: str, b_text: str, limit: int = MAX_TOKENS) -> dict[str, Any]:
    """Token-level diff: which tokens of A are absent from B."""
    all_a = _tokenize(a_text)
    a_tokens = all_a[:limit]
    b_set = set(_tokenize(b_text))
    rows = [{"token": t, "common": t in b_set} for t in a_tokens]
    changed = [r for r in rows if not r["common"]]
    return {
        "applicable": True,
        "rows": rows,
        "tokens": len(a_tokens),
        "changed": len(changed),
        "identical": not changed,
        "truncated": len(all_a) > limit,
    }


def diff_headers(a_headers: Any, b_headers: Any) -> dict[str, Any]:
    """Header-set diff, case-insensitively (HTTP header names are)."""

    def norm(h: Any) -> dict[str, str]:
        if isinstance(h, str):
            try:
                h = json.loads(h or "{}")
            except ValueError:
                return {}
        if not isinstance(h, dict):
            return {}
        return {str(k).lower(): str(v) for k, v in h.items()}

    ha, hb = norm(a_headers), norm(b_headers)
    changed, added, removed = [], [], []
    for name in sorted(set(ha) | set(hb)):
        va, vb = ha.get(name), hb.get(name)
        if va == vb:
            continue
        entry = {"name": name, "a": va, "b": vb}
        if name not in hb:
            removed.append(entry)
        elif name not in ha:
            added.append(entry)
        else:
            changed.append(entry)
    return {"changed": changed, "added": added, "removed": removed,
            "identical": not (changed or added or removed)}


_URL_PARAM_RE = re.compile(r"[?&]([^=&]+)=")


def diff_url_params(a_url: str, b_url: str) -> dict[str, Any]:
    """Which query parameters differ between two URLs.

    For access-control testing this is often the answer on its own: it names
    the parameter you flipped without making you read either URL.
    """
    from urllib.parse import parse_qsl, urlsplit

    def params(u: str) -> dict[str, str]:
        q = urlsplit(str(u or "")).query
        return {k: v for k, v in parse_qsl(q, keep_blank_values=True)}

    pa, pb = params(a_url), params(b_url)
    changed, added, removed = [], [], []
    for name in sorted(set(pa) | set(pb)):
        va, vb = pa.get(name), pb.get(name)
        if va == vb:
            continue
        entry = {"name": name, "a": va, "b": vb}
        if name not in pb:
            removed.append(entry)
        elif name not in pa:
            added.append(entry)
        else:
            changed.append(entry)
    path_a = urlsplit(str(a_url or "")).path
    path_b = urlsplit(str(b_url or "")).path
    return {
        "changed": changed, "added": added, "removed": removed,
        "path_changed": path_a != path_b,
        "path_a": path_a, "path_b": path_b,
        "method_hint": bool(_URL_PARAM_RE.search(str(a_url or ""))),
        "identical": not (changed or added or removed) and path_a == path_b,
    }


def diff_captures(a: dict, b: dict, mode: str = "auto") -> dict[str, Any]:
    """Full diff of two capture rows, picking the best available mode.

    ``mode='auto'`` prefers JSON when both bodies parse, then token, then
    char — the order that produces the most readable output for the data
    actually present.
    """
    if mode not in ("auto", "json", "token", "char"):
        raise ValueError(f"invalid diff mode: {mode!r}")

    a_body = a.get("response_body") or ""
    b_body = b.get("response_body") or ""
    out: dict[str, Any] = {
        "a": {"id": a.get("id"), "method": a.get("method"),
              "url": a.get("url"), "status": a.get("response_code"),
              "length": len(a_body)},
        "b": {"id": b.get("id"), "method": b.get("method"),
              "url": b.get("url"), "status": b.get("response_code"),
              "length": len(b_body)},
        "status": diff_status(a.get("response_code"), b.get("response_code")),
        "headers": diff_headers(a.get("response_headers"), b.get("response_headers")),
        "params": diff_url_params(a.get("url"), b.get("url")),
        "request_bodies": diff_token(a.get("body") or "", b.get("body") or ""),
        "identical": False,
        "mode": mode,
    }

    json_diff = diff_json(a_body, b_body)
    chosen = mode
    if mode == "auto":
        if json_diff["applicable"]:
            chosen = "json"
        elif a_body or b_body:
            chosen = "token"
        else:
            chosen = "char"

    if chosen == "json":
        out["body"] = json_diff
    elif chosen == "token":
        out["body"] = diff_token(a_body, b_body)
    else:
        out["body"] = diff_char(a_body, b_body)

    out["mode"] = chosen
    out["body_applicable"] = bool(out["body"].get("applicable"))
    out["identical"] = (
        out["status"] == "same"
        and out["headers"]["identical"]
        and out["params"]["identical"]
        and (out["body"].get("identical", True) if out["body_applicable"] else a_body == b_body)
        and out["request_bodies"]["identical"]
    )
    out["summary"] = _summarize(out)
    return out


def _summarize(out: dict) -> str:
    """One-line human summary for the UI header."""
    bits: list[str] = []
    if out["status"] != "same":
        bits.append(f"status {out['a']['status']} → {out['b']['status']}")
    p = out["params"]
    n_params = len(p["changed"]) + len(p["added"]) + len(p["removed"])
    if n_params:
        names = [e["name"] for e in (p["changed"] + p["added"] + p["removed"])]
        bits.append(f"{n_params} param(s): " + ", ".join(names[:4]))
    body = out["body"]
    if body.get("applicable"):
        if out["mode"] == "json":
            entries = body["changed"] + body["added"] + body["removed"]
            # A zero-count "0 JSON field(s) differ" is noise, not a summary —
            # it would make two identical captures look like a finding.
            if entries:
                # Name the paths: "1 field differs" is useless during an
                # access-control test, "role: user → admin" is the finding.
                names = ", ".join(
                    f"{e['path']}: {e['a']!r} → {e['b']!r}"
                    for e in entries[:3]
                )
                more = f" (+{len(entries) - 3} more)" if len(entries) > 3 else ""
                bits.append(f"JSON {names}{more}")
        elif out["mode"] == "token":
            if body["changed"]:
                new = [r["token"] for r in body["rows"] if not r["common"]][:3]
                bits.append(f"{body['changed']} token(s) differ: "
                            + ", ".join(new))
        elif not body.get("identical"):
            bits.append(f"bodies differ at byte {body.get('offset')}")
    elif out["a"]["length"] != out["b"]["length"]:
        bits.append(f"body {out['a']['length']}B → {out['b']['length']}B")
    h = out["headers"]
    n_h = len(h["changed"]) + len(h["added"]) + len(h["removed"])
    if n_h:
        bits.append(f"{n_h} header(s) differ")
    if not bits:
        return "identical"
    return " · ".join(bits)
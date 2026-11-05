"""Canonical HTTP scope semantics shared by CLI rules and both proxy modes."""
from __future__ import annotations

import ipaddress
import json
import os
import posixpath
import re
from urllib.parse import unquote, urlsplit


def network_scope(value: str, *, allow_wildcard: bool = False):
    if not value or any(c.isspace() or ord(c) < 32 for c in value) or "\\" in value:
        return None
    if value.startswith(("/", "./", "../", "~")):
        return None
    try:
        parsed = urlsplit(value if "://" in value else "//" + value)
        if parsed.scheme and parsed.scheme.lower() not in {"http", "https"}:
            return None
        if parsed.username is not None or parsed.password is not None or not parsed.hostname:
            return None
        host = parsed.hostname.rstrip(".").lower()
        wildcard = allow_wildcard and host.startswith("*.")
        if wildcard:
            host = host[2:]
        if "%" in host or "*" in host:
            return None
        try:
            host = str(ipaddress.ip_address(host))
        except ValueError:
            host = host.encode("idna").decode("ascii")
            if (host != "localhost" and "." not in host) or not all(
                re.fullmatch(r"[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?", label)
                for label in host.split(".")
            ):
                return None
        port = parsed.port
        if port is not None and not 1 <= port <= 65535:
            return None
        scheme = parsed.scheme.lower()
        if port is None and scheme:
            port = 443 if scheme == "https" else 80
        path = parsed.path or "/"
        for _ in range(4):
            decoded = unquote(path, errors="strict")
            if decoded == path:
                break
            path = decoded
        if "%" in path or "\\" in path or any(ord(c) < 32 for c in path):
            return None
        path = "/" + posixpath.normpath("/" + path.lstrip("/")).lstrip("/")
        return scheme, host, port, path, wildcard
    except (ValueError, UnicodeError):
        return None


def scope_contains(candidate: str, entry: str) -> bool:
    """Whether the entire candidate scope is a subset of an allowed entry."""
    target = network_scope(candidate, allow_wildcard=True)
    root = network_scope(entry, allow_wildcard=True)
    if target is None or root is None:
        return False
    scheme, host, port, path, wildcard = target
    e_scheme, e_host, e_port, e_path, e_wildcard = root
    return bool(
        (host == e_host or (e_wildcard and host.endswith("." + e_host)))
        and (not wildcard or e_wildcard)
        and (not e_scheme or scheme == e_scheme)
        and (e_port is None or port == e_port)
        and (path == e_path or path.startswith(e_path.rstrip("/") + "/"))
    )


def matches_any_scope(target: str, entries: list[str]) -> bool:
    return network_scope(target) is not None and any(scope_contains(target, e) for e in entries)


def load_scope() -> tuple[list[str], str]:
    raw = os.environ.get("MINIPROXY_SCOPE", "")
    try:
        entries = json.loads(raw) if raw else []
        if not isinstance(entries, list) or not all(isinstance(e, str) for e in entries):
            raise ValueError("Invalid scope")
    except ValueError:
        entries = ["<invalid-scope>"]  # A malformed supplied guard never disables it.
    mode = os.environ.get("MINIPROXY_SCOPE_MODE", "skip").strip().lower()
    return entries, mode if mode in {"skip", "block"} else "skip"


def load_policy(name: str) -> list[str] | None:
    raw = os.environ.get(name)
    if raw is None:
        return None
    try:
        entries = json.loads(raw)
        if not isinstance(entries, list) or not all(isinstance(e, str) for e in entries):
            raise ValueError("Invalid policy")
        return entries
    except ValueError:
        return ["<invalid-scope>"]


def request_in_scope(url: str, entries: list[str] | None,
                     allowed: list[str] | None = None, excluded: list[str] | None = None) -> bool:
    return bool(
        (not entries or matches_any_scope(url, entries))
        and (allowed is None or matches_any_scope(url, allowed))
        and (not excluded or "<invalid-scope>" not in excluded)
        and (not excluded or not matches_any_scope(url, excluded))
    )

"""Bundled wordlists for the Intruder.

Shipped inside the package so a fresh install can attack immediately instead
of hunting for a ``.txt`` first. These are deliberately small and curated —
they are the starting points for *lab and recon* traffic, not a replacement
for SecLists or a full wordlist. Each one exists because it is the payload set
you reach for constantly on a beginner-to-intermediate web lab:

``ids``        numeric IDs, for IDOR / broken access control enumeration
``usernames``  default + lab-common account names, for auth labs
``params``     parameter names, for hidden-parameter discovery
``ports``      common service ports, for SSRF / redirect validation
``paths``      common admin and API paths, for endpoint discovery

Kept as Python tuples rather than data files so they cannot go missing from a
wheel and need no packaging configuration.
"""
from __future__ import annotations

from pathlib import Path

MAX_LIST_SIZE = 1000

BUNDLED: dict[str, dict] = {
    "ids": {
        "title": "Numeric IDs",
        "description": "1-100: the classic starting point for IDOR enumeration.",
        "words": [str(i) for i in range(1, 101)],
    },
    "usernames": {
        "title": "Common usernames",
        "description": "Default and lab-common account names for auth testing.",
        "words": [
            "admin", "administrator", "root", "user", "test", "guest",
            "info", "support", "service", "operator", "manager", "superuser",
            "sysadmin", "webmaster", "postgres", "mysql", "oracle",
            "wiener", "carlos", "alice", "bob", "eve", "mallory", "tom",
            "jerry", "bruce", "default", "demo", "dev", "developer", "api",
        ],
    },
    "passwords": {
        "title": "Common passwords",
        "description": "Deliberately obvious defaults for auth testing. "
                       "Local lab use only.",
        "words": [
            "password", "password1", "Password1", "admin", "admin123",
            "administrator", "letmein", "welcome", "welcome1", "changeme",
            "secret", "123456", "12345678", "qwerty", "abc123", "monkey",
            "dragon", "iloveyou", "trustno1", "sunshine", "princess",
            "football", "baseball", "passw0rd", "p@ssw0rd", "test123",
        ],
    },
    "params": {
        "title": "Parameter names",
        "description": "Common parameter names, for hidden-parameter discovery.",
        "words": [
            "id", "user", "username", "userid", "uid", "name", "role",
            "admin", "password", "pass", "email", "session", "sessionid",
            "token", "api_key", "apikey", "key", "secret", "debug", "page",
            "search", "q", "query", "filter", "sort", "order", "limit",
            "offset", "file", "path", "redirect", "url", "next", "return",
            "csrf", "csrf_token", "code", "state", "auth", "remember",
        ],
    },
    "ports": {
        "title": "Common ports",
        "description": "Service ports, for SSRF and redirect validation.",
        "words": [str(p) for p in (
            21, 22, 25, 53, 80, 110, 135, 139, 143, 443, 445, 993, 995,
            1433, 1521, 2049, 3000, 3306, 3389, 5432, 5900, 6379, 8000,
            8080, 8443, 8888, 9000, 9090, 9200, 27017,
        )],
    },
    "paths": {
        "title": "Common paths",
        "description": "Admin, API and config paths for endpoint discovery.",
        "words": [
            "admin", "administrator", "login", "logout", "signin", "signup",
            "register", "dashboard", "panel", "config", "configuration",
            "settings", "api", "api/v1", "api/v2", "graphql", "rest",
            "health", "status", "debug", "test", "backup", "backups", "dump",
            "db", "database", "phpinfo.php", "info.php", "server-status",
            ".env", ".git/config", "actuator", "actuator/env", "swagger",
            "docs", "robots.txt", "sitemap.xml", "uploads", "download",
        ],
    },
}


def list_wordlists() -> list[dict]:
    """Metadata for every bundled list (no words — that keeps it cheap)."""
    return [
        {
            "name": name,
            "title": meta["title"],
            "description": meta["description"],
            "count": len(meta["words"]),
        }
        for name, meta in sorted(BUNDLED.items())
    ]


def get_wordlist(name: str) -> dict | None:
    """One list including its words, capped at :data:`MAX_LIST_SIZE`."""
    meta = BUNDLED.get(str(name or "").strip().lower())
    if meta is None:
        return None
    return {
        "name": str(name).strip().lower(),
        "title": meta["title"],
        "description": meta["description"],
        "count": len(meta["words"]),
        "words": list(meta["words"][:MAX_LIST_SIZE]),
    }


def load_from_file(path: str | Path, limit: int = MAX_LIST_SIZE) -> list[str]:
    """Read a user-supplied wordlist, skipping blanks and comments.

    Comments matter: wordlists copied out of blog posts routinely start with
    `#`, and a leading ``#`` sent as a payload is a wasted request at best.
    """
    out: list[str] = []
    for raw in Path(path).read_text(errors="replace").splitlines():
        line = raw.strip()
        if not line or line.startswith("#"):
            continue
        out.append(line)
        if len(out) >= limit:
            break
    return out
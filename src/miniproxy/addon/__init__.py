"""MiniProxy addon package — the canonical v4 mitmproxy addon.

``proxy.py`` and ``db.py`` are loaded by mitmdump BY PATH (``mitmdump -s
.../addon/proxy.py``); the ``__init__.py`` exists so the same files are
importable as a regular package (tests, tooling) via the try/except import
at the top of ``proxy.py``.
"""

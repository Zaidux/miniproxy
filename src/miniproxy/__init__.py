"""MiniProxy — a lightweight HTTP/S interception proxy for security research.

Ships the canonical v4 capture engine (the same addon the Riciplay CLI
embeds): always-on capture, static-asset streaming, per-flow TTFB/total
timing, and a RULES-style scope guard with skip/block modes — plus a Flask
dashboard (Log / Repeater / Intruder) and a small manager CLI.
"""

__version__ = "0.4.0"

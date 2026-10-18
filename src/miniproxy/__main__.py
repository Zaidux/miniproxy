"""MiniProxy entry point — ``miniproxy`` / ``python -m miniproxy``.

Subcommands:
  start      Start the interception proxy (mitmdump + v4 addon) — the web
             dashboard is launched alongside and its URL printed, unless
             --no-dashboard is given. Capture is unchanged either way.
  stop       Stop the proxy (and the dashboard)
  status     Proxy + dashboard status
  dashboard  Run the Flask dashboard in the foreground
  web        Start the proxy AND the web dashboard in one step (alias of
             `start` with the dashboard forced on)
  connect    Print exactly how to point any browser/device (here or
             anywhere on the internet) at the running proxy — QR included
  tui        Run the terminal UI (Textual) — live feed, details, repeater
  send       Send a request through the dashboard's Repeater
  log        Show captured requests
  version    Print the MiniProxy version
"""
from __future__ import annotations

import argparse
import os
import sys
from urllib.parse import urlsplit, urlunsplit


def _pasteable_dashboard_url(url: str) -> str:
    """Defend the paste-ability contract at print time.

    server.py already swaps a wildcard bind (``0.0.0.0``) for a detected
    LAN/VPS host; this last-mile check covers any other code path that
    might hand back a bind address. ``0.0.0.0`` is a bind address, not a
    destination — pasting it into a browser is what produced the infamous
    "printed a URL but the page is blank" VPS report.
    """
    try:
        parts = urlsplit(url)
    except ValueError:
        return url
    if (parts.hostname or "") not in ("0.0.0.0", "::", "*"):
        return url
    try:
        from miniproxy import connect as connect_helpers

        for candidate in connect_helpers.candidate_hosts(include_loopback=False):
            host = str(candidate.get("host", "")).strip()
            if host and not host.lower().startswith(("169.254.", "fe80:", "fec0:")):
                netloc = f"{host}:{parts.port}" if parts.port else host
                return urlunsplit(
                    (parts.scheme, netloc, parts.path, parts.query, parts.fragment))
    except Exception:  # pragma: no cover - best-effort guard
        pass
    # No discoverable address: fall back to loopback, mirroring
    # server._dashboard_display_host. The printed reachability notes then
    # point at the SSH tunnel / explicit-exposure steps for other devices.
    netloc = f"127.0.0.1:{parts.port}" if parts.port else "127.0.0.1"
    return urlunsplit((parts.scheme, netloc, parts.path, parts.query, parts.fragment))


def _dashboard_reachability_notes(dash_host: str, dash_port: int | str) -> list[str]:
    """Human guidance about where the dashboard URL actually works.

    The #1 remote-setup confusion (seen on a real VPS): the CLI prints
    ``Web UI: http://127.0.0.1:5000``, the user opens it on their *phone*,
    and 127.0.0.1 there is the phone itself — ERR_CONNECTION_REFUSED. Say
    which device the URL belongs to and how to reach it from others.
    """
    if dash_host in ("127.0.0.1", "localhost", "::1"):
        return [
            "ℹ  That URL works only on the machine running miniproxy — "
            "127.0.0.1 on your phone/laptop is that device, not this one.",
            "   From another device:  ssh -L "
            f"{dash_port}:127.0.0.1:{dash_port} user@<vps>  "
            f"then open http://127.0.0.1:{dash_port} on YOUR machine, or",
            "   expose it:  miniproxy stop && miniproxy start "
            f"--dashboard-host 0.0.0.0 --dashboard-token <secret>"
            f"  →  http://<vps-ip>:{dash_port}/connect",
        ]
    notes: list[str] = []
    try:
        from miniproxy import connect as connect_helpers

        hosts = connect_helpers.candidate_hosts(include_loopback=False)
        if hosts:
            notes.append(
                f"ℹ  From any device:  http://{hosts[0]['host']}:{dash_port}/connect"
                "  (make sure this port is open in the VPS firewall/security group)."
            )
    except Exception:  # pragma: no cover - guidance is best-effort
        pass
    return notes


def _port_arg(value: str) -> int | str:
    """--port values: an int, or 'auto' for always-pick-a-free-port."""
    text = str(value).strip().lower()
    if text in ("auto", "0"):
        return "auto"
    try:
        return int(text)
    except ValueError:
        raise argparse.ArgumentTypeError(
            f"invalid port {value!r} — use a number or 'auto'") from None


def _same_option(p: argparse.ArgumentParser, flag: str) -> dict:
    """Copy an option's kwargs from one subparser to build it on another.

    ``type`` must come along too — without it ``miniproxy web --port 9999"
    parsed the port as a *string*, which server.start() then wrote to the
    port file verbatim.
    """
    for action in p._actions:
        if flag in action.option_strings:
            kwargs = {
                "default": action.default,
                "help": action.help,
                "type": action.type,
            }
            # `nargs` must come along too: `--scope` is nargs="*" on start, so
            # the alias rejected `miniproxy web --scope a.example b.example`
            # with "unrecognized arguments" and broke a bare `--scope`.
            if action.nargs is not None:
                kwargs["nargs"] = action.nargs
            if action.__class__.__name__ == "_StoreTrueAction":
                kwargs = {"action": "store_true", "help": action.help}
            elif action.__class__.__name__ == "_AppendAction":
                # Repeatable flags (--allow-client IP) must stay repeatable on
                # the aliased subparser; without this they collapse to a bare
                # string and the caller iterates it one character at a time.
                kwargs = {
                    "action": "append",
                    "default": action.default,
                    "help": action.help,
                    "metavar": action.metavar,
                }
            return kwargs
    return {"default": None}


def _version() -> str:
    try:
        from importlib.metadata import version as _v

        return _v("riciplay-miniproxy")
    except Exception:
        return "unknown"


def build_parser() -> argparse.ArgumentParser:
    """Construct the full CLI parser.

    Kept separate from main() so a parser-construction bug (e.g. a
    duplicated subparser, which used to crash *every* invocation with
    ``conflicting subparser: web``) is caught by tests instead of only
    showing up on a user's machine.
    """
    parser = argparse.ArgumentParser(
        prog="miniproxy",
        description="HTTP/S interception proxy for security research.",
    )
    sub = parser.add_subparsers(dest="command")

    p_start = sub.add_parser("start", help="Start the interception proxy (+ web dashboard)")
    p_start.add_argument("--port", type=_port_arg, default=8080,
                         help="Proxy listen port (default 8080; 'auto' always "
                              "picks a free port; a busy port moves up)")
    p_start.add_argument("--db", default=None, help="SQLite capture DB path")
    p_start.add_argument("--scope", nargs="*", default=None,
                         help="Capture-scope hosts (*.domain wildcards); "
                              "out-of-scope traffic is not captured")
    p_start.add_argument("--block-out-of-scope", action="store_true",
                         help="403-block out-of-scope traffic instead of passing it through")
    p_start.add_argument("--mitmdump", default="mitmdump")
    p_start.add_argument("--dashboard-port", type=_port_arg, default=5000,
                         help="Port for the web dashboard (default 5000; "
                              "'auto'/busy → next free port)")
    p_start.add_argument("--dashboard-host", default="127.0.0.1",
                         help="Bind address for the web dashboard "
                              "(default 127.0.0.1; pass 0.0.0.0 explicitly for LAN access)")
    p_start.add_argument("--dashboard-token", default=None,
                         help="Require this token for the dashboard's mutating "
                              "endpoints (recommended with --dashboard-host 0.0.0.0)")
    p_start.add_argument("--no-dashboard", action="store_true",
                         help="Do not launch the web dashboard")
    p_start.add_argument("--proxy-host", default="127.0.0.1",
                         help="Bind address for the PROXY port "
                              "(default 127.0.0.1 = not reachable from the "
                              "internet; reach it via `ssh -L <port>:127.0.0.1:"
                              "<port>`). Pass 0.0.0.0 to publish it.")
    p_start.add_argument("--allow-client", action="append", default=None,
                         metavar="IP",
                         help="LIMIT WHICH DESTINATIONS get intercepted "
                              "(repeatable). NOT a client allowlist: despite "
                              "the name this is mitmproxy's allow_hosts, which "
                              "filters destination hosts. It does NOT stop "
                              "anyone who can reach the port from proxying "
                              "other destinations, so it does not close an "
                              "open relay. For that use a firewall, or keep "
                              "the proxy on loopback and tunnel over SSH. "
                              "e.g. --allow-client 203.0.113.7")

    p_web = sub.add_parser("web", help="Start the proxy AND the web dashboard (alias of start)")
    for opt in ("--port", "--db", "--scope", "--mitmdump", "--dashboard-port",
                "--dashboard-host", "--dashboard-token", "--no-dashboard",
                "--proxy-host", "--allow-client"):
        p_web.add_argument(opt, **_same_option(p_start, opt))
    p_web.add_argument("--block-out-of-scope", action="store_true")

    sub.add_parser("stop", help="Stop the proxy and the dashboard")
    sub.add_parser("status", help="Proxy + dashboard status")

    p_dash = sub.add_parser("dashboard", help="Run the Flask dashboard")
    p_dash.add_argument("--port", type=_port_arg, default=5000)
    p_dash.add_argument("--host", default="127.0.0.1")
    p_dash.add_argument("--token", default=None,
                        help="Require a token on mutating endpoints")

    p_connect = sub.add_parser(
        "connect",
        help="Print how to point any browser/device at the running proxy",
    )
    p_connect.add_argument("--host", default=None,
                           help="Override the advertised proxy host (default: "
                                "auto-detect the best reachable address)")
    p_connect.add_argument("--port", type=int, default=None,
                           help="Override the advertised proxy port "
                                "(default: the running proxy, else 8080)")
    p_connect.add_argument("--qr", choices=["auto", "yes", "no"], default="auto",
                           help="Print a scannable ANSI QR of the dashboard "
                                "connect URL (default: auto — yes on a TTY)")

    p_tui = sub.add_parser("tui", help="Run the terminal UI (Textual)")
    p_tui.add_argument("--db", default=None, help="SQLite capture DB path")
    p_tui.add_argument("--refresh", type=float, default=2.0,
                       help="Poll interval in seconds (default 2.0)")

    p_send = sub.add_parser("send", help="Send a request via the dashboard Repeater")
    p_send.add_argument("--url", required=True)
    p_send.add_argument("--method", default="GET")
    p_send.add_argument("--headers", default="{}", help="JSON object of headers")
    p_send.add_argument("--body", default="")

    p_log = sub.add_parser("log", help="Show captured requests")
    p_log.add_argument("--id", type=int, default=None)
    p_log.add_argument("--limit", type=int, default=30)

    p_noise = sub.add_parser(
        "noise",
        help="Manage browser-noise rules and clean captured noise",
        description="Browser telemetry drowns out the target. These rules make "
                    "matched traffic skip the capture DB entirely; `clean` "
                    "removes noise already captured.",
    )
    noise_sub = p_noise.add_subparsers(dest="noise_action")

    p_nl = noise_sub.add_parser("list", help="Show noise rules and their state")
    p_nl.add_argument("--db", default=None, help="capture DB path")

    p_na = noise_sub.add_parser("add", help="Ignore a host from now on")
    p_na.add_argument("hosts", nargs="+", help="host or *.suffix pattern")
    p_na.add_argument("--db", default=None, help="capture DB path")

    p_nr = noise_sub.add_parser("rm", help="Stop ignoring a host")
    p_nr.add_argument("hosts", nargs="+")
    p_nr.add_argument("--db", default=None)

    p_ne = noise_sub.add_parser("enable", help="Enable rules (all, or the listed ones)")
    p_ne.add_argument("hosts", nargs="*", help="hosts to enable; omit for all")
    p_ne.add_argument("--db", default=None)

    p_nd = noise_sub.add_parser("disable", help="Disable rules")
    p_nd.add_argument("hosts", nargs="*")
    p_nd.add_argument("--db", default=None)

    p_ns = noise_sub.add_parser("scan", help="Dry run: what would be removed")
    p_ns.add_argument("--db", default=None)

    p_nc = noise_sub.add_parser("clean", help="Delete captured noise (backs up first)")
    p_nc.add_argument("--yes", "-y", action="store_true", help="confirm the deletion")
    p_nc.add_argument("--keep-host", action="append", default=None,
                      help="never delete captures from this host (repeatable)")
    p_nc.add_argument("--db", default=None)

    sub.add_parser("version", help="Print the MiniProxy version")

    return parser


def _open_db(db_path=None):
    """Open the capture DB the same way `log` does (proxy.db under STATE_DIR).

    Precedence matches the rest of the CLI: explicit --db, then
    MINIPROXY_DB_PATH, then the default session DB.
    """
    from miniproxy.addon.db import Database
    from miniproxy.server import STATE_DIR

    return Database(db_path or os.environ.get("MINIPROXY_DB_PATH")
                    or (STATE_DIR / "proxy.db"))


def _cmd_noise(args) -> int:
    """`miniproxy noise …` — manage telemetry/ad rules and clean old captures.

    Split out of main() because it is the only subcommand with its own
    verbs; the point of it is that noise can be handled without the dashboard
    running (over SSH, on a headless box).
    """
    action = args.noise_action

    if action == "list":
        db = _open_db(getattr(args, "db", None))
        rules = db.list_noise_rules()
        if not rules:
            print("(no noise rules)")
            return 0
        print(f"{'ON':<4} {'KIND':<7} VALUE")
        print("-" * 60)
        for r in rules:
            mark = "yes" if r["enabled"] else "no "
            tag = " (bundled)" if r["builtin"] else ""
            print(f"{mark:<4} {r['kind']:<7} {r['value']}{tag}")
        enabled = sum(1 for r in rules if r["enabled"])
        print(f"\n{enabled}/{len(rules)} enabled · matched traffic is never captured.")
        return 0

    if action in ("add", "rm", "enable", "disable"):
        db = _open_db(getattr(args, "db", None))
        values = getattr(args, "hosts", None) or []

        def _norm(host: str) -> str:
            # A rule may be written with or without the wildcard prefix;
            # store and match it the same way.
            return str(host).strip().lower().lstrip("*").lstrip(".")

        try:
            if action in ("add", "rm"):
                # Both address a specific host, so they require one.
                if not values:
                    print(f"error: `noise {action}` needs at least one host",
                          file=sys.stderr)
                    return 2
                for host in values:
                    if action == "add":
                        db.add_noise_rule(host, kind="host", enabled=True)
                        print(f"added rule: {host}")
                    else:
                        # Compare normalized on both sides: a rule stored as
                        # "*.youtube.com" must be removable by "youtube.com".
                        want_norm = _norm(host)
                        targets = [r for r in db.list_noise_rules()
                                   if _norm(r["value"]) == want_norm]
                        if not targets:
                            print(f"no rule for {host}", file=sys.stderr)
                            return 1
                        for t in targets:
                            db.delete_noise_rule(t["id"])
                        print(f"removed rule: {host}")
                return 0

            # enable/disable: no hosts means "all of them" — the one-click
            # opt-in for the bundled telemetry list.
            want = action == "enable"
            if values:
                targets = [r for r in db.list_noise_rules()
                           if _norm(r["value"]) in {_norm(v) for v in values}]
                if not targets:
                    print("no matching rules", file=sys.stderr)
                    return 1
            else:
                targets = db.list_noise_rules()
            changed = 0
            for r in targets:
                if bool(r["enabled"]) != want:
                    db.set_noise_rule_enabled(r["id"], want)
                    changed += 1
            scope = f"{len(targets)} rule(s)" if values else "all rules"
            print(f"{scope}: {changed} {action}d")
            if not values and want:
                print("Matched hosts will no longer be captured.")
            return 0
        except ValueError as exc:
            print(f"error: {exc}", file=sys.stderr)
            return 2

    if action == "scan":
        db = _open_db(getattr(args, "db", None))
        scan = db.scan_noise(keep_hosts=getattr(args, "keep_host", None) or [])
        print(f"{scan['matched']} capture(s) would be removed, {scan['keep']} kept.")
        if scan["by_host"]:
            print(f"\n{'HOST':<50} ROWS")
            print("-" * 58)
            for row in scan["by_host"]:
                print(f"{row['host'][:50]:<50} {row['removed']:>4}")
        print("\nNothing was deleted. Re-run with `noise clean` to apply.")
        return 0

    if action == "clean":
        db = _open_db(getattr(args, "db", None))
        scan = db.scan_noise(keep_hosts=getattr(args, "keep_host", None) or [])
        if not scan["matched"]:
            print("nothing to clean.")
            return 0
        if not args.yes:
            # Refuse without confirmation — this deletes captured traffic.
            print(f"This would delete {scan['matched']} capture(s) "
                  f"({scan['keep']} kept).")
            for row in scan["by_host"][:10]:
                print(f"  {row['host']}: {row['removed']}")
            print("\nRe-run with --yes to apply (a .noise-backup-*.db is written).")
            return 1
        try:
            result = db.clean_noise(keep_hosts=getattr(args, "keep_host", None) or [])
        except db.NoiseBackupError as exc:
            print(f"error: {exc}", file=sys.stderr)
            return 1
        print(f"removed {result['removed']} capture(s).")
        if result["backup"]:
            print(f"backup: {result['backup']}")
        return 0

    return 1


def main(argv: list[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)

    if args.command == "version":
        print(_version())
        return 0

    if args.command in ("start", "web"):
        from miniproxy import server
        dash_host = getattr(args, "dashboard_host", None) or "127.0.0.1"
        result = server.start(
            port=args.port, db_path=args.db, scope_hosts=args.scope,
            out_of_scope="block" if args.block_out_of_scope else "skip",
            mitmdump_path=args.mitmdump,
            dashboard=not args.no_dashboard,
            dash_port=args.dashboard_port,
            dash_host=dash_host,
            dash_token=args.dashboard_token,
            allow_clients=getattr(args, "allow_client", None),
            proxy_host=getattr(args, "proxy_host", "127.0.0.1"),
        )
        # The proxy always runs with block_global=false so a remote browser
        # can point at it. Combined with a non-loopback bind that is an open
        # relay: any host that can reach the port captures through it and
        # lands in the DB. Warn loudly rather than silently collecting
        # someone else's traffic.
        proxy_host = getattr(args, "proxy_host", "127.0.0.1")
        published = proxy_host not in ("127.0.0.1", "localhost", "::1")
        if published and not getattr(args, "allow_client", None):
            print("⚠  Proxy port %s is published on %s with NO client "
                  "restriction (open relay). Anyone who reaches it can proxy "
                  "and capture. --allow-client will NOT fix this — it filters "
                  "destination hosts, not clients. Use a firewall, or keep the "
                  "proxy on loopback and tunnel over SSH."
                  % (result.get("port") or args.port, proxy_host))
        if published and getattr(args, "allow_client", None):
            print("⚠  --allow-client filters DESTINATION hosts, not clients — "
                  "it does not restrict who may connect to this port.")
        if published:
            print("ℹ  Proxy published on %s — remote browsers must reach it "
                  "at <this-server>:%s. Loopback (the default) needs "
                  "`ssh -L %s:127.0.0.1:%s` from the client."
                  % (proxy_host, result.get("port") or args.port,
                     result.get("port") or args.port,
                     result.get("port") or args.port))
        if dash_host not in ("127.0.0.1", "localhost") and not args.dashboard_token:
            print("⚠  Dashboard is LAN-exposed with NO auth: captures contain tokens, "
                  "cookies and session data. Pass --dashboard-token to require auth.")
        print(result["message"])
        dash = result.get("dashboard") or {}
        if dash.get("fallback"):
            print("ℹ  Dashboard port was busy — it bound :%s instead. "
                  "Use this port in the dashboard URL." % dash.get("port"))
        elif result.get("fallback"):
            print("ℹ  Requested port was busy — the proxy took :%s instead. "
                  "Point clients at this port." % result.get("port"))
        dash_error = (result.get("dashboard") or {}).get("status") == "error"
        dash_url = (result.get("dashboard") or {}).get("url")
        if dash_error:
            # The proxy started but the dashboard did not. Reading ["url"]
            # raised KeyError, so the user got a traceback after a success
            # message instead of the actual problem.
            print("⚠  The dashboard did not start: %s"
                  % (result["dashboard"].get("message") or "unknown error"),
                  file=sys.stderr)
        elif dash_url:
            dash_url = _pasteable_dashboard_url(dash_url)
            # The URL a user is told to paste must open the web UI, not be a
            # bind address (0.0.0.0) or the proxy port (8080) — the proxy
            # speaks CONNECT/HTTP-proxy, which a browser address bar cannot
            # render. server.py already swaps wildcard binds for a detected
            # LAN/VPS address; here we make the paste-ability explicit.
            print(f"Web UI: {dash_url}   ← paste this into your browser to use "
                  "MiniProxy (mirrors `miniproxy tui`)")
            print(f"Connect: {dash_url.rstrip('/')}/connect   — wizard to route "
                  "any other browser/device through the proxy")
            for note in _dashboard_reachability_notes(
                    dash_host, dash.get("port", args.dashboard_port)):
                print(note)
        return 0 if result["status"] in ("started", "already_running") else 1

    if args.command == "stop":
        from miniproxy import server
        result = server.stop()
        print(result["message"])
        dash = server.stop_dashboard()
        print(dash["message"])
        ok = result["status"] in ("stopped", "not_running") and dash["status"] in ("stopped", "not_running")
        return 0 if ok else 1

    if args.command == "status":
        from miniproxy import server
        result = server.status()
        print(result["message"])
        dash_port = result.get("dashboard")
        if result["status"] == "running" and dash_port:
            print(f"Web UI: http://127.0.0.1:{dash_port}   "
                  "← paste into a browser on this machine")
            print("   (loopback — reachable only from the VPS itself; see `miniproxy "
                  "connect` for other devices)")
        return 0 if result["status"] == "running" else 1

    if args.command == "dashboard":
        import miniproxy.app as appmod
        dash_port = args.port
        if dash_port == "auto":
            from miniproxy.server import _next_free_port
            dash_port = _next_free_port(5000) or 5000
        if args.token:
            os.environ["MINIPROXY_DASHBOARD_TOKEN"] = args.token
            appmod.DASHBOARD_TOKEN = args.token
        if args.host not in ("127.0.0.1", "localhost") and not args.token:
            print("⚠  Dashboard is LAN-exposed with NO auth: captures contain tokens, "
                  "cookies and session data. Pass --token to require auth.")
        appmod.app.run(host=args.host, port=dash_port, debug=False)
        return 0

    if args.command == "connect":
        # 'From a terminal, how do I capture my browser on another device?'
        # — resolved addresses, PAC/CA URLs, curl one-liners, and a QR.
        # The dashboard does not need to be running (defaults are shown).
        from miniproxy import connect as connect_helpers
        from miniproxy import qrcode
        from miniproxy import server

        st = server.status()
        proxy_port = args.port or st.get("port") or server.DEFAULT_PORT
        # Prefer the explicitly configured dashboard port when known.
        dash_port = st.get("dashboard") or server.DEFAULT_DASH_PORT
        dash_host = args.host or connect_helpers.candidate_hosts(include_loopback=False)
        dash_host = args.host or (dash_host[0]["host"] if dash_host else "127.0.0.1")

        proxy_addr = f"{dash_host}:{proxy_port}"
        base = f"http://{dash_host}:{dash_port}"
        ca = connect_helpers.ca_cert_path()
        print("\n═══ Connect any browser or device to MiniProxy ═══\n")
        print(f"  HTTP proxy to enter in browser/OS settings:  {proxy_addr}")
        state_note = "running" if st["status"] == "running" else "NOT RUNNING — start it with `miniproxy start`"
        print(f"  Proxy status: {state_note}")
        print("")
        print("  1 · Point the browser at the proxy:")
        print(f"       manual        →  HTTP proxy {proxy_addr}")
        print(f"       PAC URL       →  {base}/proxy.pac   (paste into browser/OS 'automatic proxy config')")
        print("")
        print("  2 · Trust the CA to see HTTPS bodies (HTTP works without it):")
        print(f"       download      →  {base}/ca.crt")
        if ca.is_file():
            print(f"       on this host  →  {ca}")
        else:
            print("       (not generated yet — run `mitmdump` once on the proxy host)")
        print("")
        print("  3 · Or capture terminal tools directly:")
        print(f"       curl -x http://{proxy_addr} https://example.com")
        print(f"       export http_proxy=http://{proxy_addr} https_proxy=http://{proxy_addr}")
        print("")
        print(f"  Full wizard (open in any browser):  {base}/connect")
        show_qr = args.qr == "yes" or (args.qr == "auto" and sys.stdout.isatty())
        if show_qr:
            try:
                print("\n  Scan to open the connect page on a phone:\n")
                print(qrcode.qr_terminal(base + "/connect"))
            except ValueError as exc:
                print(f"\n  (QR unavailable: {exc})")
        elif args.qr == "yes":
            print("\n  (QR requested but output is not a TTY — skipping)")
        print("")
        print("  ⚠ Intercept only traffic you are authorized to test.")
        print("  Detailed guide: docs/connect.md\n")
        return 0

    if args.command == "tui":
        # The TUI needs a real terminal; refuse to hang inside pipes/CI.
        if not sys.stdin.isatty() or not sys.stdout.isatty():
            print("Error: `miniproxy tui` needs an interactive terminal.",
                  file=sys.stderr)
            return 1
        from miniproxy.tui import run_tui
        return run_tui(db_path=args.db, refresh=args.refresh)

    if args.command == "send":
        # Direct request — no dashboard needed (mirrors the Repeater API's
        # semantics: no redirects, self-signed certs allowed, 15s timeout).
        import json as _json

        import requests
        import urllib3

        urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)
        try:
            headers = _json.loads(args.headers)
            if not isinstance(headers, dict):
                headers = {}
        except ValueError:
            print("Error: --headers must be a JSON object", file=sys.stderr)
            return 1
        try:
            resp = requests.request(
                method=args.method.upper(), url=args.url, headers=headers,
                data=args.body, timeout=15, verify=False, allow_redirects=False,
            )
        except requests.RequestException as exc:
            print(f"Error: {exc}", file=sys.stderr)
            return 1
        print(f"Status: {resp.status_code}")
        print(f"Headers: {_json.dumps(dict(resp.headers), indent=2)}")
        body_text = resp.text or ""
        print(f"Body ({len(body_text)} chars):")
        print(body_text[:2000] + ("..." if len(body_text) > 2000 else ""))
        return 0

    if args.command == "log":
        # Reads the capture DB directly — the dashboard does not need to
        # be running to inspect what the proxy captured.
        from miniproxy.addon.db import Database
        from miniproxy.server import STATE_DIR

        db = Database(os.environ.get("MINIPROXY_DB_PATH") or (STATE_DIR / "proxy.db"))
        if args.id is not None:
            row = db.get_request(args.id)
            if row is None:
                print(f"No captured request with id={args.id}.", file=sys.stderr)
                return 1
            print(f"ID:      {row.get('id')}")
            print(f"Method:  {row.get('method')}")
            print(f"URL:     {row.get('url')}")
            print(f"Status:  {row.get('response_code')}")
            print(f"TTFB:    {row.get('ttfb_ms')} ms | Total: {row.get('total_ms')} ms")
            print(f"Headers: {str(row.get('headers') or '')[:500]}")
            print(f"Body:    {str(row.get('body') or '')[:1000]}")
            return 0
        logs = db.get_logs(limit=max(args.limit, 1))
        print(f"{'ID':>4} {'METHOD':<7} {'STATUS':<5} {'MS':>7}  URL")
        print("-" * 72)
        for r in logs:
            ms = r.get("total_ms")
            ms_s = f"{ms:.0f}" if isinstance(ms, (int, float)) else "?"
            print(f"{r.get('id', '?'):>4} {r.get('method', '?'):<7} "
                  f"{r.get('response_code', '?'):<5} {ms_s:>7}  "
                  f"{str(r.get('url', ''))[:60]}")
        if not logs:
            print("(no captured requests yet)")
        return 0

    if args.command == "noise":
        return _cmd_noise(args)

    parser.print_help()
    return 1


if __name__ == "__main__":
    sys.exit(main())

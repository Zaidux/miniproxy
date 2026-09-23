"""MiniProxy TUI — terminal dashboard for the capture DB and the proxy.

A Textual app that reads the SQLite capture DB directly (the dashboard does
not need to be running), while proxy start/stop/status and Repeater requests
run in worker threads so the UI never blocks.

Layout
------
    ┌ proxy status ───────────────────────────────────────────────┐
    ├─────────────────────────────────────────────────────────────┤
    │ [method ▾] [status ▾] [ url substring…                ]     │
    ├──────────────────────────────┬──────────────────────────────┤
    │ live capture table           │ Request / Response /         │
    │ (ID Method Status ms URL)    │ Intruder detail panes        │
    ├──────────────────────────────┴──────────────────────────────┤
    │ footer: key shortcuts                                       │
    └─────────────────────────────────────────────────────────────┘

Keys
----
    r  Repeater      i  Intruder results    c  copy curl
    y  copy body     p  toggle proxy        R  force refresh
    f/t/s  focus URL/method/status filter
    j/k or arrows  move      g/G or home/end  jump
    ?  help         q  quit
"""
from __future__ import annotations

import json
import os
import shlex
from datetime import datetime
from pathlib import Path
from typing import Any

from textual import work
from textual.app import App, ComposeResult
from textual.binding import Binding
from textual.coordinate import Coordinate
from textual.containers import Horizontal, Vertical
from textual.screen import ModalScreen
from textual.widgets import (
    Button,
    DataTable,
    Footer,
    Input,
    Label,
    RichLog,
    Select,
    Static,
    TabbedContent,
    TabPane,
    TextArea,
)

from miniproxy.addon.db import Database
from miniproxy.server import (
    STATE_DIR,
    start as proxy_start,
    status as proxy_status,
    stop as proxy_stop,
)

METHODS = ["GET", "POST", "PUT", "DELETE", "PATCH", "HEAD", "OPTIONS", "CONNECT"]


# ── Helpers ─────────────────────────────────────────────────────────────


def _json_headers(raw: Any) -> dict[str, str]:
    """SQLite stores headers as JSON text; tolerate legacy dicts/None."""
    if isinstance(raw, dict):
        return {str(k): str(v) for k, v in raw.items()}
    try:
        parsed = json.loads(raw or "{}")
    except (json.JSONDecodeError, TypeError):
        return {}
    return {str(k): str(v) for k, v in parsed.items()} if isinstance(parsed, dict) else {}


def as_curl(row: dict[str, Any]) -> str:
    """Render a captured request as a copy-pasteable curl command."""
    method = str(row.get("method") or "GET").upper()
    url = str(row.get("url") or "")
    parts = ["curl", "-sS", "-i", "-X", method, shlex.quote(url)]
    for k, v in _json_headers(row.get("headers")).items():
        parts += ["-H", shlex.quote(f"{k}: {v}")]
    body = row.get("body")
    if body:
        parts += ["--data-raw", shlex.quote(str(body))]
    return " ".join(parts)


def _fmt_ms(value: Any) -> str:
    return f"{float(value):.0f}" if isinstance(value, (int, float)) else "—"


def _code_color(code: Any) -> str:
    if code == 0:
        return "red"
    if isinstance(code, int):
        if 200 <= code < 300:
            return "green"
        if 300 <= code < 400:
            return "yellow"
        if code >= 400:
            return "red"
    return "dim"


# ── Widgets & screens ───────────────────────────────────────────────────


class DetailViewer(RichLog):
    """Scrollable pane that renders rich renderables (panels, syntax, tables)."""

    def __init__(self, pane_id: str) -> None:
        super().__init__(id=pane_id, markup=True, wrap=True, highlight=False, auto_scroll=False)
        self._last_renderable: Any = None

    def load(self, renderable: Any) -> None:
        self._last_renderable = renderable
        self.clear()
        self.write(renderable)


class HelpScreen(ModalScreen[None]):
    """Full-screen keybinding cheatsheet."""

    CSS = """
    HelpScreen {
        align: center middle;
        background: $surface;
    }
    #help-wrap {
        width: 78;
        max-width: 92%;
        height: auto;
        max-height: 88%;
        padding: 1 2;
        border: round $accent;
        background: $surface;
    }
    #help-close { margin-top: 1; }
    """

    BINDINGS = [Binding("escape,question_mark", "dismiss_screen", "Close")]

    def compose(self) -> ComposeResult:
        from rich.table import Table

        grid = Table.grid(padding=(0, 2))
        grid.add_column(style="bold cyan", justify="right")
        grid.add_column()
        for key, desc in [
            ("r", "Repeater for the selected request"),
            ("i", "Intruder results for the selected request"),
            ("c", "Copy request as curl to clipboard"),
            ("y", "Copy response body to clipboard"),
            ("e", "Save response body to a file"),
            ("p", "Toggle the proxy (start / stop)"),
            ("R", "Force-refresh the request table"),
            ("f / t / s", "Focus URL / method / status filter"),
            ("j k / ↑ ↓", "Move in the request table"),
            ("g G / home end", "Jump to top / bottom"),
            ("enter", "Open the Repeater (same as r)"),
            ("?", "Toggle this help"),
            ("q", "Quit"),
        ]:
            grid.add_row(key, desc)
        yield Vertical(
            Label("[b]MiniProxy — keys[/b]"),
            Static(grid),
            Button("Close", id="help-close", variant="primary"),
            id="help-wrap",
        )

    def action_dismiss_screen(self) -> None:
        self.dismiss()

    def on_button_pressed(self, event: Button.Pressed) -> None:
        if event.button.id == "help-close":
            self.dismiss()


class RepeaterModal(ModalScreen[None]):
    """Edit and resend a captured request; shows the live response."""

    CSS = """
    RepeaterModal { align: center middle; background: $surface; }
    #rep-grid {
        width: 96%; max-width: 140;
        height: 96%;
        padding: 1 2;
        border: round $accent;
        background: $surface;
    }
    #rep-title { text-style: bold; margin-bottom: 1; }
    #rep-row-top { height: auto; }
    #rep-method { width: 16; margin-right: 1; }
    #rep-url { width: 1fr; }
    #rep-headers { height: 8; margin-top: 1; border: tall $panel; }
    #rep-body { height: 8; margin-top: 1; border: tall $panel; }
    #rep-actions { height: auto; margin-top: 1; }
    #rep-send { margin-right: 1; }
    #rep-out-meta { padding: 0 1; width: 1fr; }
    #rep-split { height: 1fr; margin-top: 1; }
    #rep-out-viewer { width: 1fr; border: tall $panel; }
    """

    BINDINGS = [
        Binding("escape", "close", "Close"),
        # priority=True so the binding wins over the focused TextArea
        Binding("ctrl+s", "send", "Send", priority=True),
    ]

    def __init__(self, row: dict[str, Any], **kwargs: Any) -> None:
        super().__init__(**kwargs)
        self._row = row

    def compose(self) -> ComposeResult:
        header_lines = "\n".join(
            f"{k}: {v}" for k, v in _json_headers(self._row.get("headers")).items()
        )
        yield Vertical(
            Label(
                f"[b]Repeater[/b] — {self._row.get('method', 'GET')} {self._row.get('url', '')}",
                id="rep-title",
            ),
            Horizontal(
                Select(
                    options=[(m, m) for m in METHODS],
                    value=str(self._row.get("method") or "GET").upper(),
                    prompt="Method",
                    allow_blank=False,
                    id="rep-method",
                ),
                Input(
                    value=str(self._row.get("url") or ""),
                    placeholder="https://target/api",
                    id="rep-url",
                ),
                id="rep-row-top",
            ),
            TextArea.code_editor(header_lines, soft_wrap=True, show_line_numbers=False, id="rep-headers"),
            TextArea.code_editor(str(self._row.get("body") or ""), soft_wrap=True, show_line_numbers=False, id="rep-body"),
            Horizontal(
                Button("Send (Ctrl+S)", id="rep-send", variant="success"),
                Button("Close (Esc)", id="rep-close"),
                Static("", id="rep-out-meta"),
                id="rep-actions",
            ),
            Horizontal(DetailViewer("rep-out-viewer"), id="rep-split"),
            id="rep-grid",
        )

    def action_close(self) -> None:
        self.dismiss()

    def on_button_pressed(self, event: Button.Pressed) -> None:
        if event.button.id == "rep-send":
            self.action_send()
        elif event.button.id == "rep-close":
            self.dismiss()

    def action_send(self) -> None:
        method = str(self.query_one("#rep-method", Select).value or "GET")
        url = self.query_one("#rep-url", Input).value.strip()
        if not url:
            self.app.notify("URL is required", severity="warning")
            return
        headers: dict[str, str] = {}
        for line in self.query_one("#rep-headers", TextArea).text.splitlines():
            if ":" in line:
                key, _, value = line.partition(":")
                headers[key.strip()] = value.strip()
        body = self.query_one("#rep-body", TextArea).text
        self._do_send(method, url, headers, body)

    @work(thread=True, exclusive=True, group="repeater-send")
    def _do_send(self, method: str, url: str, headers: dict[str, str], body: str) -> None:
        import requests
        import urllib3

        urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)
        try:
            resp = requests.request(
                method=method, url=url, headers=headers, data=body,
                timeout=15, verify=False, allow_redirects=False,
            )
            payload: dict[str, Any] = {
                "status_code": resp.status_code,
                "headers": dict(resp.headers),
                "body": resp.text[:100_000],
            }
        except requests.RequestException as exc:
            payload = {"error": str(exc)}
        self.app.call_from_thread(self._show_response, payload)

    def _show_response(self, payload: dict[str, Any]) -> None:
        from rich.console import Group
        from rich.json import JSON
        from rich.panel import Panel
        from rich.text import Text

        meta = self.query_one("#rep-out-meta", Static)
        viewer = self.query_one("#rep-out-viewer", DetailViewer)
        if "error" in payload:
            meta.update(f"[b red]Error[/b red] {payload['error']}")
            self.app.notify("Repeater request failed", severity="error", timeout=5)
            return
        code = int(payload["status_code"])
        meta.update(f"[b]Response[/b] [{_code_color(code)}]{code}[/{_code_color(code)}] · {len(payload.get('body') or '')} chars")
        header_block = Text()
        for k, v in (payload.get("headers") or {}).items():
            header_block.append(f"{k}: ", style="bold")
            header_block.append(f"{v}\n", style="dim")
        body = str(payload.get("body") or "")
        try:
            body_block: Any = JSON(body)
        except Exception:
            body_block = Text(body or "(empty body)")
        viewer.load(
            Group(
                Panel(header_block, title="Headers", border_style="dim"),
                Panel(body_block, title="Body", border_style="dim"),
            )
        )


# ── Main app ────────────────────────────────────────────────────────────


class MiniProxyTUI(App[None]):
    """MiniProxy terminal UI — live feed, details, Repeater, Intruder, proxy."""

    TITLE = "MiniProxy"
    SUB_TITLE = "HTTP/S interception proxy — terminal UI"

    CSS = """
    #proxy-bar {
        height: auto;
        padding: 0 1;
        background: $panel;
    }
    #proxy-status { margin-right: 2; }
    #proxy-db { color: $text-muted; }
    #main { height: 1fr; }
    #filters { height: auto; padding: 0 1; }
    #filter-method { width: 18; margin-right: 1; }
    #filter-status { width: 16; margin-right: 1; }
    #filter-url { width: 1fr; }
    #split { height: 1fr; }
    #requests { width: 1fr; min-width: 44; border: tall $panel; }
    #detail-pane { width: 56; border: tall $panel; }
    #req-meta { height: auto; padding: 0 1; color: $text-muted; }
    #detail-tabs { height: 1fr; }
    #detail-bottom { height: auto; padding: 0 1; }
    #detail-bottom Button { margin-right: 1; }
    TabPane { padding: 0 1; }
    """

    BINDINGS = [
        Binding("q", "quit", "Quit"),
        Binding("question_mark", "help", "Help"),
        Binding("p", "toggle_proxy", "Proxy"),
        Binding("r,enter", "open_repeater", "Repeater"),
        Binding("i", "show_intruder", "Intruder"),
        Binding("c", "copy_curl", "Copy curl"),
        Binding("y", "copy_body", "Copy body"),
        Binding("e", "save_body", "Save body"),
        Binding("f", "focus_url_filter", "URL filter"),
        Binding("t", "focus_method_filter", "Method"),
        Binding("s", "focus_status_filter", "Status"),
        Binding("R", "force_refresh", "Refresh"),
        Binding("j,down", "cursor_down", show=False),
        Binding("k,up", "cursor_up", show=False),
        Binding("g,home", "cursor_top", show=False),
        Binding("G,end", "cursor_bottom", show=False),
    ]

    def __init__(self, db_path: str | None = None, refresh: float = 2.0) -> None:
        super().__init__()
        self._db_path = db_path or os.environ.get("MINIPROXY_DB_PATH") or str(STATE_DIR / "proxy.db")
        self.db = Database(self._db_path)
        self._rows_by_key: dict[str, dict[str, Any]] = {}
        self._last_sig: tuple | None = None
        self._proxy_status_text = "unknown"
        self._refresh_s = max(float(refresh), 0.5)

    # ── Layout ──────────────────────────────────────────────────────────

    def compose(self) -> ComposeResult:
        with Horizontal(id="proxy-bar"):
            yield Static("", id="proxy-status")
            yield Static(f"db: {self._db_path}", id="proxy-db")
        with Vertical(id="main"):
            with Horizontal(id="filters"):
                yield Select(
                    options=[("All", "")] + [(m, m) for m in METHODS],
                    prompt="Method", allow_blank=True, id="filter-method",
                )
                yield Select(
                    options=[("All", ""), ("2xx", "2"), ("3xx", "3"), ("4xx", "4"),
                             ("5xx", "5"), ("Errors", "0"), ("Pending", "pending")],
                    prompt="Status", allow_blank=True, id="filter-status",
                )
                yield Input(placeholder="Filter by URL substring…", id="filter-url")
            with Horizontal(id="split"):
                yield DataTable(id="requests", cursor_type="row", zebra_stripes=True)
                with Vertical(id="detail-pane"):
                    yield Static("", id="req-meta")
                    with TabbedContent(id="detail-tabs"):
                        with TabPane("Request", id="tab-req"):
                            yield DetailViewer("viewer-request")
                        with TabPane("Response", id="tab-resp"):
                            yield DetailViewer("viewer-response")
                        with TabPane("Intruder", id="tab-int"):
                            yield DetailViewer("viewer-intruder")
                    with Horizontal(id="detail-bottom"):
                        yield Button("Repeater (r)", id="btn-repeater", variant="primary")
                        yield Button("Intruder (i)", id="btn-intruder")
                        yield Button("Copy curl (c)", id="btn-curl")
                        yield Button("Copy body (y)", id="btn-body")
        yield Footer()

    def on_mount(self) -> None:
        self.query_one("#requests", DataTable).add_columns("ID", "Method", "Status", "ms", "URL")
        self._refresh_table(force=True)
        self._refresh_proxy_state()
        self.set_interval(self._refresh_s, self._poll)

    # ── Polling ─────────────────────────────────────────────────────────

    def _poll(self) -> None:
        self._refresh_table()
        self._refresh_proxy_state()

    # ── Capture table ───────────────────────────────────────────────────

    def _row_matches(self, row: dict[str, Any]) -> bool:
        def _sel_text(widget: Select) -> str:
            value = widget.value
            return "" if value is Select.NULL or value is None else str(value)

        method = _sel_text(self.query_one("#filter-method", Select)).upper()
        status = _sel_text(self.query_one("#filter-status", Select))
        url_sub = self.query_one("#filter-url", Input).value.strip().lower()
        if method and str(row.get("method") or "").upper() != method:
            return False
        code = row.get("response_code")
        if status == "pending":
            if code is not None:
                return False
        elif status == "0":
            if code != 0:
                return False
        elif status in ("2", "3", "4", "5"):
            if not isinstance(code, int) or code // 100 != int(status):
                return False
        if url_sub and url_sub not in str(row.get("url") or "").lower():
            return False
        return True

    def _refresh_table(self, force: bool = False) -> None:
        try:
            rows = self.db.get_logs(limit=200)
        except Exception as exc:  # DB may be mid-write; retry on next tick
            self.log(f"capture read failed: {exc}")
            return
        sig = tuple(
            (r.get("id"), r.get("response_code"), r.get("total_ms")) for r in rows
        )
        if not force and sig == self._last_sig:
            return
        self._last_sig = sig

        selected_id = None
        current = self._selected_row()
        if current is not None:
            selected_id = current.get("id")

        table = self.query_one("#requests", DataTable)
        table.clear(columns=True)
        self._rows_by_key.clear()
        table.add_columns("ID", "Method", "Status", "ms", "URL")
        for row in rows:
            if not self._row_matches(row):
                continue
            code = row.get("response_code")
            code_label = "…" if code is None else ("ERR" if code == 0 else str(code))
            key = f"row-{row.get('id')}"
            table.add_row(
                str(row.get("id") or ""),
                str(row.get("method") or ""),
                code_label,
                _fmt_ms(row.get("total_ms")),
                str(row.get("url") or ""),
                key=key,
            )
            self._rows_by_key[key] = row

        # Restore the cursor to the previously selected request when it
        # survives the refresh (and the current filters); otherwise land on
        # the newest row so the detail pane is never stale/empty.
        if selected_id is not None:
            for key, row in self._rows_by_key.items():
                if row.get("id") == selected_id:
                    try:
                        table.move_cursor(row=table.get_row_index(key))
                    except Exception:
                        pass
                    break
        current = self._selected_row()
        if current is not None:
            self._show_detail(current)

    def _selected_row(self) -> dict[str, Any] | None:
        table = self.query_one("#requests", DataTable)
        if table.row_count == 0:
            return None
        try:
            row_index = min(max(table.cursor_row, 0), table.row_count - 1)
            cell_key = table.coordinate_to_cell_key(Coordinate(row_index, 0))
        except Exception:
            return None
        return self._rows_by_key.get(str(cell_key.row_key.value))

    # ── Proxy status & toggle ──────────────────────────────────────────

    def _refresh_proxy_state(self) -> None:
        try:
            st = proxy_status()
        except Exception as exc:
            self.log(f"proxy status failed: {exc}")
            return
        self._proxy_status_text = st["status"]
        label = self.query_one("#proxy-status", Static)
        if st["status"] == "running":
            label.update(
                f"[b]proxy[/b] [green]running[/green] :{st.get('port')} (pid {st.get('pid')})"
            )
        else:
            label.update("[b]proxy[/b] [red]stopped[/red] — [dim]p to start[/dim]")

    @work(thread=True, exclusive=True, group="proxy-toggle")
    def action_toggle_proxy(self) -> None:
        """Start/stop the proxy off the UI thread (start can block ~8s)."""
        try:
            running = self._proxy_status_text == "running"
            result = proxy_stop() if running else proxy_start()
        except Exception as exc:
            result = {"status": "error", "message": f"proxy toggle failed: {exc}"}

        def _done() -> None:
            self._proxy_status_text = result["status"]
            self._refresh_proxy_state()
            severity = (
                "information"
                if result["status"] in ("started", "stopped", "already_running")
                else "error"
            )
            self.notify(result["message"], severity=severity, timeout=6)

        self.app.call_from_thread(_done)

    # ── Filters ─────────────────────────────────────────────────────────

    def on_select_changed(self, event: Select.Changed) -> None:
        if event.select.id in ("filter-method", "filter-status"):
            self._refresh_table(force=True)

    def on_input_changed(self, event: Input.Changed) -> None:
        if event.input.id == "filter-url":
            self._refresh_table(force=True)

    def action_focus_url_filter(self) -> None:
        self.query_one("#filter-url", Input).focus()

    def action_focus_method_filter(self) -> None:
        self.query_one("#filter-method", Select).focus()

    def action_focus_status_filter(self) -> None:
        self.query_one("#filter-status", Select).focus()

    def action_force_refresh(self) -> None:
        self._refresh_table(force=True)
        self._refresh_proxy_state()
        self.notify("Refreshed", timeout=1)

    # ── Cursor movement ─────────────────────────────────────────────────

    def action_cursor_down(self) -> None:
        table = self.query_one("#requests", DataTable)
        table.move_cursor(row=table.cursor_row + 1)

    def action_cursor_up(self) -> None:
        table = self.query_one("#requests", DataTable)
        table.move_cursor(row=max(table.cursor_row - 1, 0))

    def action_cursor_top(self) -> None:
        self.query_one("#requests", DataTable).move_cursor(row=0)

    def action_cursor_bottom(self) -> None:
        table = self.query_one("#requests", DataTable)
        table.move_cursor(row=max(table.row_count - 1, 0))

    # ── Detail pane ─────────────────────────────────────────────────────

    def on_data_table_row_highlighted(self, event: DataTable.RowHighlighted) -> None:
        row = self._rows_by_key.get(str(event.row_key.value))
        if row is not None:
            self._show_detail(row)

    def _show_detail(self, row: dict[str, Any]) -> None:
        from rich.console import Group
        from rich.panel import Panel
        from rich.syntax import Syntax
        from rich.text import Text

        code = row.get("response_code")
        color = _code_color(code)
        meta = self.query_one("#req-meta", Static)
        meta.update(
            f"[b]#{row.get('id')}[/b] · {row.get('method')} · "
            f"[{color}]{code if code is not None else '…'}[/{color}] · "
            f"ttfb {_fmt_ms(row.get('ttfb_ms'))}ms · total {_fmt_ms(row.get('total_ms'))}ms · "
            f"{str(row.get('url') or '')}"
        )

        req_line = Text()
        req_line.append(f"{row.get('method')} ", style="bold magenta")
        req_line.append(f"{row.get('url')}\n", style="bold")
        for k, v in _json_headers(row.get("headers")).items():
            req_line.append(f"{k}: ", style="bold")
            req_line.append(f"{v}\n", style="dim")
        body = str(row.get("body") or "")
        # Truncation notice for the request body (original length recorded
        # at capture time in request_body_len).
        req_len = row.get("request_body_len")
        req_note = (
            f" ⚠ truncated at {len(body)} B (original {req_len} B)"
            if isinstance(req_len, int) and req_len > len(body)
            else ""
        )
        if body:
            try:
                body_block: Any = Syntax(body, "json", theme="ansi_dark", word_wrap=True)
            except Exception:
                body_block = Text(body)
        else:
            body_block = Text("(empty body)", style="dim italic")
        self.query_one("#viewer-request", DetailViewer).load(
            Group(
                Panel(req_line, title="Request line & headers", border_style="dim"),
                Panel(body_block, title=f"Body{req_note}", border_style="dim"),
            )
        )

        resp_viewer = self.query_one("#viewer-response", DetailViewer)
        if code is None:
            resp_viewer.load(Text("(pending — response not captured yet)", style="dim italic"))
            return
        if code == 0:
            err = _json_headers(row.get("response_headers")).get("_error", "flow error")
            resp_viewer.load(Text(f"(transport error: {err})", style="bold red"))
            return
        resp_headers = Text()
        for k, v in _json_headers(row.get("response_headers")).items():
            resp_headers.append(f"{k}: ", style="bold")
            resp_headers.append(f"{v}\n", style="dim")
        resp_body = str(row.get("response_body") or "")
        content_type = str(row.get("content_type") or "")
        # Truncation notice: bodies are stored capped (default 100 KB); the
        # *_body_len columns record the original size, so we can say so.
        resp_len = row.get("response_body_len")
        resp_note = (
            f" ⚠ truncated at {len(resp_body)} B (original {resp_len} B)"
            if isinstance(resp_len, int) and resp_len > len(resp_body)
            else ""
        )
        if "json" in content_type and resp_body:
            try:
                resp_body_block: Any = Syntax(resp_body, "json", theme="ansi_dark", word_wrap=True)
            except Exception:
                resp_body_block = Text(resp_body)
        else:
            resp_body_block = Text(resp_body or "(empty body)")
        resp_viewer.load(
            Group(
                Panel(resp_headers, title=f"Response {code}", border_style="dim"),
                Panel(resp_body_block, title=f"Body ({content_type or 'unknown type'}){resp_note}", border_style="dim"),
            )
        )

    # ── Intruder ────────────────────────────────────────────────────────

    def action_show_intruder(self) -> None:
        row = self._selected_row()
        if row is None:
            self.notify("Select a captured request first", severity="warning")
            return
        self.query_one("#detail-tabs", TabbedContent).active = "tab-int"
        # The pane's widgets mount asynchronously after the tab switch —
        # defer the DB read until the next refresh so the viewer exists.
        self.call_after_refresh(self._load_intruder_results, int(row.get("id") or 0))

    def _load_intruder_results(self, request_id: int) -> None:
        from rich.panel import Panel
        from rich.table import Table
        from rich.text import Text

        viewer = self.query_one("#viewer-intruder", DetailViewer)
        try:
            results = self.db.get_intruder_results(request_id)
        except Exception as exc:
            viewer.load(Text(f"(failed to read intruder results: {exc})", style="red"))
            return
        if not results:
            viewer.load(
                Text(
                    "(no intruder results for this request — run one from the web dashboard)",
                    style="dim italic",
                )
            )
            return
        table = Table(box=None, pad_edge=False)
        table.add_column("payload", style="cyan", no_wrap=True, overflow="ellipsis", max_width=36)
        table.add_column("code", justify="right")
        table.add_column("ms", justify="right")
        table.add_column("len", justify="right")
        for r in results:
            code = r.get("response_code")
            table.add_row(
                str(r.get("payload") or ""),
                Text(str(code), style=_code_color(code)),
                _fmt_ms(r.get("ttfb_ms")),
                str(len(str(r.get("response_body") or ""))),
            )
        viewer.load(Panel(table, title=f"Intruder results for #{request_id}", border_style="dim"))

    # ── Clipboard ───────────────────────────────────────────────────────

    def action_copy_curl(self) -> None:
        row = self._selected_row()
        if row is None:
            self.notify("Select a captured request first", severity="warning")
            return
        try:
            self.copy_to_clipboard(as_curl(row))
            self.notify("curl command copied", timeout=2)
        except Exception as exc:
            self.notify(f"copy failed: {exc}", severity="error", timeout=4)

    def action_copy_body(self) -> None:
        row = self._selected_row()
        if row is None:
            self.notify("Select a captured request first", severity="warning")
            return
        body = str(row.get("response_body") or "")
        if not body:
            self.notify("No response body captured", severity="warning")
            return
        try:
            self.copy_to_clipboard(body)
            self.notify("response body copied", timeout=2)
        except Exception as exc:
            self.notify(f"copy failed: {exc}", severity="error", timeout=4)

    def action_save_body(self) -> None:
        """Write the selected row's response body to a timestamped file.

        The CLI can't pop a native save dialog, so we write next to the cwd
        (falling back to the state dir) and tell the user where it landed.
        """
        row = self._selected_row()
        if row is None:
            self.notify("Select a captured request first", severity="warning")
            return
        body = str(row.get("response_body") or "")
        if not body:
            self.notify("No response body captured", severity="warning")
            return
        stem = os.path.basename((row.get("url") or "request").rstrip("/").split("?")[0]) or f"body-{row.get('id', 'x')}"
        stem = "".join(c for c in stem if c.isalnum() or c in "._-") or f"body-{row.get('id', 'x')}"
        target_dir = Path.cwd() if os.access(Path.cwd(), os.W_OK) else STATE_DIR
        target = target_dir / f"miniproxy-{stem[:40]}-{datetime.now():%Y%m%d-%H%M%S}.txt"
        try:
            target.write_text(body, encoding="utf-8", errors="replace")
        except OSError as exc:
            self.notify(f"save failed: {exc}", severity="error", timeout=4)
            return
        self.notify(f"saved → {target}", timeout=4)

    # ── Repeater & help ─────────────────────────────────────────────────

    def action_open_repeater(self) -> None:
        row = self._selected_row()
        if row is None:
            self.notify("Select a captured request first", severity="warning")
            return
        self.push_screen(RepeaterModal(row))

    def action_help(self) -> None:
        self.push_screen(HelpScreen())

    # ── Buttons ─────────────────────────────────────────────────────────

    def on_button_pressed(self, event: Button.Pressed) -> None:
        button_id = event.button.id or ""
        if button_id == "btn-repeater":
            self.action_open_repeater()
        elif button_id == "btn-intruder":
            self.action_show_intruder()
        elif button_id == "btn-curl":
            self.action_copy_curl()
        elif button_id == "btn-body":
            self.action_copy_body()


def run_tui(db_path: str | None = None, refresh: float = 2.0) -> int:
    """Entry point used by ``miniproxy tui``."""
    app = MiniProxyTUI(db_path=db_path, refresh=refresh)
    app.run()
    return 0

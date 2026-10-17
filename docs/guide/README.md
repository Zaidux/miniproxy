# MiniProxy: a beginner's guide

This guide explains **what each part of MiniProxy is for** and **how to use it
on a real lab**, in plain language. It is written for someone working through
PortSwigger Web Security Academy or a bug-bounty practice lab with the
dashboard, usually on a phone.

You do not need to know Python, Flask, or how to read the source. You do need
to know what a request, a response, a header, and a parameter are.

If you already know the tool and want the reference material, use the
maintainer docs instead: [Web UI](../web-ui.md), [CLI & TUI](../cli-and-tui.md),
[Connect](../connect.md), [Setup](../setup.md). This guide links to them where
they go deeper, and does not repeat them.

## How every feature is described

Each feature gets the same five parts, so you always know where to look:

- **What it's for** — the job it does, not how it works inside.
- **How to use it** — numbered steps with the exact labels you see on screen.
- **Worked example** — a concrete lab-style task.
- **What to look for** — how to tell it worked.
- **Common mistakes / notes** — including the surprising parts. Where the
  current build has a limit, it says so instead of pretending.

Labels are written in **bold** (a button, tab, or chip) or `code` (a value,
path, or exact text). They match the dashboard's spelling.

## Read in this order

1. **[Getting started](getting-started.md)** — install, start the proxy and
   dashboard, point a browser or phone at it, and confirm traffic is captured.
2. **[The Live tab](live-tab.md)** — the capture table, filters, host focus,
   body search, the detail pane, Pretty/Raw/Hex, notes, highlights, the **⋮**
   menu, the Log tab, export and clear.
3. **[Repeater](repeater.md)** — edit one request and resend it, with tabs,
   history, and follow-redirects.
4. **[Intruder](intruder.md)** — `§placeholder§` fuzzing with one list or a
   different list per position, bundled wordlists, pasting your own, and how to
   read the results: sorting, filtering, isolating the outliers, and comparing
   two responses.
5. **[Diff](diff.md)** — compare two captures (or two Intruder results) and
   read off what changed.
6. **[Noise control](noise.md)** — stop browser junk at capture time, hide it
   at view time, and clean it out with a dry run and a backup.
7. **[Rewrite](rewrite.md)** — match-and-replace on live traffic, before the
   target sees it.
8. **[Connect](connect.md)** — the wizard that gets another browser or device
   onto the proxy.
9. **[Common workflows](workflows.md)** — username enumeration, password
   guessing, IDOR checks, hidden-parameter discovery, and keeping a lab tidy.
10. **[Glossary](glossary.md)** — the words this guide uses, including
    `§placeholder§`, pitchfork, capture, and scope.

## If you are on a phone

The dashboard is responsive at about 412px wide, and the important controls
are tap targets. A few differences from the desktop:

- The tab bar wraps onto more than one line. That is normal.
- The Live tab stacks: the capture table first, the detail pane below it.
  Tap the divider (or drag it) to hide or show the detail pane.
- The **⋮** button on each row is pinned to the right edge of the table so it
  never scrolls out of reach. It is the only row menu; there is no right-click.
- In the Repeater modal, **Send (Ctrl+S)** is a button. The Ctrl+S shortcut is
  for a keyboard.
- In the Intruder, the Pitchfork rows stack their controls. **Paste** stays on
  the first line, the list picker and file box move below it.

Getting the dashboard itself onto the phone is the one part that needs a
decision (LAN address or SSH tunnel). [Getting started](getting-started.md)
covers it, and [Connect](../connect.md) has the per-platform detail.

## What this guide leaves out

- The TUI and CLI have their own documentation:
  [CLI & TUI](../cli-and-tui.md).
- Internals, the database schema, and the HTTP API are in
  [Web UI](../web-ui.md) and [Code audit](../AUDIT.md).

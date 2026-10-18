# Noise control

A browser drags in telemetry pings, ad beacons, new-tab thumbnails, fonts, and
JavaScript bundles. On a real Web Security Academy run, one browser session
produced 119 captured rows, of which 12 were on target. Reading that table is
the hard part of the lab, not the lab itself.

MiniProxy attacks noise in three layers. They do different jobs, and mixing
them up is the usual source of "where did my capture go?".

| Layer | When it acts | Deletes anything? |
|-------|--------------|-------------------|
| **1. Capture-time rules** | before a row is written | No, prevents the row |
| **2. Query-time filters** | while you look at the table | No |
| **3. Cleanup** | on demand, with a preview and a backup | Yes |

The reference is [Web UI → Noise](../web-ui.md#noise--the-browser-noise-problem).
The same rules are available without the dashboard:
[`miniproxy noise`](../cli-and-tui.md#noise).

## Layer 1: drop hosts at capture time

**What it's for.** Stop the junk before it reaches the database. Matching hosts
are still proxied normally; only the capture is skipped. This is the layer that
keeps the database small and the table readable from the start.

**How to use it.**

1. Open the **Noise** tab.
2. To add one host, type it into
   `Host to ignore, e.g. *.telemetry.example.com` and click **Add**.
3. To use the shipped list of common browser telemetry and ad hosts, click
   **Enable bundled list**. It ships disabled on purpose.
4. Toggle an individual rule with its checkbox. The header shows
   `N of M enabled`.
5. Remove a rule with **Remove**.

**Worked example.** Firefox talks to `incoming.telemetry.mozilla.org`,
`detectportal.firefox.com`, `img-getpocket.cdn.mozilla.net`, and several
Google/Microsoft background services during a normal session. Click **Enable
bundled list**, then browse the lab. Those hosts no longer appear in **Live**.
Your target's rows do.

**What to look for.** New traffic from a matching host stops appearing. On a
fresh database the header count goes from `0 of 28 enabled` to `28 of 28
enabled` after **Enable bundled list** (the toast is `Bundled telemetry/ad rules
enabled`). Adding a single host shows `Rule added — new traffic to X will not be
captured`.

**Common mistakes / notes.**

- **Rules only affect future traffic.** A rule added now does nothing to rows
  already in the database. Use layer 2 to hide them, or layer 3 to delete them.
- **Matching is host-based, exact-or-suffix.** `example.com` matches
  `example.com` and `a.example.com`. `*.example.com` does the same. It does
  not match `notexample.com`, and it cannot match a path: the Add box rejects
  anything containing `/` (`noise host rules take a host, not a URL path`).
- **Capture-time rules do not drop static assets**, and they do not apply to
  Repeater or Intruder requests (those do not go through the proxy). Static
  assets are a layer 2/3 concept.
- **`Enable bundled list` affects only the bundled rules.** A custom rule you
  disabled stays disabled — the button does what its name says. (The CLI's
  `noise enable` is a bulk "all on"; the dashboard and TUI are scoped.)
- A disabled rule keeps its place in the list. Disabling stops future drops;
  it does not restore rows that were already skipped (they were never stored).

## Layer 2: hide what is already captured

**What it's for.** You do not want to delete anything yet, but you do want the
noise out of your face. These are the same filters described in
[The Live tab](live-tab.md#narrow-the-list-with-filters), used with noise in
mind.

**How to use it.**

1. Open **Live**.
2. Focus the target with **All hosts**. The dropdown labels each host with its
   capture count, so the noisy one is obvious.
3. Tick **Hide static** for images, fonts, CSS, JS and media.
4. Read the summary on the right of the filter bar: `37 shown / 119 fetched`
   and the two busiest hosts with their counts.
5. Tick **Highlighted** to narrow to findings.
6. To manage the rules that produce that summary, click **Noise…** in the
   filter bar. It switches to the Noise tab.

**Worked example.** The Live table is unreadable. Open **All hosts**, pick the
lab host with `(12)` next to it. The table is now 12 rows. Then tick **Hide
static** if the lab host itself serves a lot of assets.

**What to look for.** The count line changes, and the busiest-host hint stops
naming the host you focused on.

**Common mistakes / notes.**

- These filters **hide**, they do not delete. The rows are still in the
  database and in a HAR/JSON export unless the filter is active at export time.
- **Hide static** is decided by content type first, then by extension. An
  endpoint named `/api/image.png` that returns JSON is API traffic and stays.
- The host count includes static assets and is computed over recent captures,
  not the current view.
- The summary is a hint, not a control: clicking it does nothing. Use
  **Noise…** to manage rules.

## Layer 3: clean up with a dry run and a backup

**What it's for.** Delete the noise that is already in the database, safely:
preview the blast radius, then delete with a timestamped backup.

**How to use it.**

1. Open the **Noise** tab. A scan runs automatically when the tab opens.
2. Click **Scan (dry run)** at any time. It never deletes.
3. Read the result: `N noise · M kept`, and a list of hosts with
   `N row(s)` next to each.
4. When the numbers look right, click **Delete N noise captures…**. The button
   is disabled when the scan found nothing.
5. Confirm the dialog. Read it first: it names the count and says a backup is
   written.
6. Read the toast: `Removed N captures · backup: <path>`.

**Worked example.** You enabled the bundled telemetry list after an hour of
browsing, so the old junk is still in the database. Open **Noise**, read the
preview (say, 107 noise · 12 kept), and delete. The 12 kept rows survive, future
telemetry is skipped at capture time, and the backup sits next to the database
file. Check the per-host list first: static assets on the lab host count as
noise too, so "12 kept" is not necessarily "12 lab API calls".

**What to look for.**

- The preview's `N noise` and `M kept` add up to the captures in the database.
- The per-host list explains where the deletions come from. If a host you care
  about is in that list, do not confirm.
- After deletion the toast names the backup file, for example
  `proxy.db.noise-backup-20261017-093012.db`.
- The rules stay enabled, so the same hosts are skipped in future.

**Common mistakes / notes.**

- **The cleanup always treats every static asset as noise, whether or not you
  have any rule enabled.** A scan with zero rules can still propose deleting
  every image, font, CSS and JS capture. "Static assets are always eligible"
  in the tab's hint means exactly this. Read the per-host preview before you
  confirm.
- **Deleting a capture deletes its Intruder results too.** If an attack's base
  request is noise, the results go with it.
- The backup is written only when there is something to delete. It is a full
  copy of the database at that moment, not just the removed rows. Backups are
  not pruned by MiniProxy; delete old ones yourself.
- The backup path is only shown in a toast, which disappears after a couple of
  seconds. The file is next to the capture database (same directory, name
  `<db>.noise-backup-<date>.db`); the database path is in the dashboard header.
- The confirmation is a normal browser dialog. If you dismiss it, nothing is
  deleted.
- Cleanup is not reversible from the UI. Restoring means stopping MiniProxy and
  putting the backup file in place of the database.
- **Automatic pruning is a fourth, invisible layer.** The default limits
  (5,000 rows / 7 days / 50 MB) delete the oldest captures and their Intruder
  results without asking. If a row vanished and you did not run a cleanup,
  that is the likely reason.
- Noise rules are per database. A new lab database starts with the bundled
  rules present but disabled.

Next: [Rewrite](rewrite.md).

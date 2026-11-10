# CLI automation and investigation contracts

MiniProxy 0.9.8 keeps human output as the default and adds versioned JSON
contracts that do not require a dashboard:

```bash
miniproxy capabilities --json
miniproxy addon-manifest --json
miniproxy start --no-dashboard --port auto --db ./capture.db --json
miniproxy status --json
miniproxy health --json
miniproxy log --db ./capture.db --host target.example --limit 100 --json
miniproxy endpoints --db ./capture.db --host target.example --json
miniproxy export --db ./capture.db --format jsonl --limit 100
miniproxy stop --json
```

`schema_version` is currently 1. Errors have nonzero exit codes. `status` reports
the launched session's DB and scope, not the current caller's environment.
Legacy ownership files without a session manifest have unknown metadata rather
than a guessed DB. Explicit `--db` or `MINIPROXY_DB_PATH` still overrides readers.
Programmatic `extra_args` cannot override the owned listener, proxy mode or addon
script; use the corresponding explicit startup parameters. Conflicting overrides
are rejected before spawn so recorded session metadata remains truthful.
Omitted capture scope retains `MINIPROXY_SCOPE` when supplied; malformed capture
or canonical RULES/exclusion policies fail preflight instead of weakening the
guard. Explicit scope must be a nonempty canonical list.

Evidence commands open existing databases read-only and never create or migrate
a missing/old capture. Missing files/schema return an error rather than a false
empty/complete inventory. Metadata/sidecar disagreement is an integrity error;
health never calls contradictory listener metadata ready.

## Readiness is not upstream verification

`health` distinguishes `process_alive`, `listener_ready`, and `capture_ready`.
It only connects to the recorded local listener and opens the capture DB read-only.
It never sends a third-party CONNECT request. `forwarding_verified` stays false:
a local readiness check cannot prove that a target is reachable or a particular
browser operation was captured. A missing/incompatible proxy runtime makes
readiness fail. The resolved `ca_certificate_path` comes from the existing CA
configuration.

Use a separate, operator-owned fixture request when forwarding verification is
required. Successful browsing and successful capture are different observations.

## Filtered cursor queries

`log --json` and `export` apply host/method/status/URL/body filters in SQLite before
the page limit. `next_cursor` is an exclusive descending capture-ID boundary:

```bash
miniproxy log --db capture.db --host target.example --limit 100 --json
miniproxy log --db capture.db --host target.example --limit 100 --before-id 123 --json
```

`has_more`, `matched_count`, and items refer to the same read transaction. New
capture inserts do not repeat older cursor pages. `--since-id` provides an
exclusive lower bound. Limits are 1..5000; invalid values are rejected.

JSONL emits one `type=metadata` record containing continuation/count metadata,
then `type=flow` records. It is a bounded page, not an unbounded dump. Raw headers
and bodies may contain credentials: protect exports and do not send them to a
model or remote log without an explicit redaction policy.

Python consumers can use `miniproxy.automation.query(db, ...)`,
`endpoint_inventory(db, ...)`, `capabilities()`, and `addon_manifest()`, and
`miniproxy.server.health()`. Endpoint inventory retains blank/flag query
parameters and returns example flow IDs, bounded-window hit counts and explicit
`complete`/continuation metadata; it never implies an unscanned capture is complete.
Existing DB methods remain supported.

## Capture fidelity

The legacy object-shaped `headers` and `response_headers` remain for older
consumers. New `headers_raw`/`response_headers_raw` fields preserve ordered
duplicates such as multiple Set-Cookie fields. Use them for faithful export;
splitting the legacy comma-joined value cannot reconstruct those boundaries.
HAR export uses the ordered representation when present.
Model-facing adapters must also redact or omit the new raw header fields; sanitizing
only the legacy header dictionaries does not protect their ordered counterparts.
The same applies to new evidence metadata when writing shared logs or reports.

`request_body_state`, `response_body_state`, omitted reasons and `flow_outcome`
distinguish a complete empty response from pending, intentionally unretained,
truncated or failed evidence. Structured `application/*+json`/`*+xml` bodies are
retained subject to UTF-8 byte limits. Static/binary/SSE policy omissions are
explicit; they are not complete zero-byte bodies. Body fidelity remains bounded
text capture—not a promise of unlimited binary/stream capture.

## Addon provenance and CLI upgrades

Packaged manual interception uses a private `<capture.db>.intercept/` directory.
Launchers and consumers can agree on another per-session location with
`MINIPROXY_INTERCEPT_STATE_DIR` and
`miniproxy.addon.intercept_addon.resolve_intercept_state_paths(...)`.
Path-deployed legacy addons still use sibling queue files when the launcher
precreated them (or explicitly selects legacy mode), preserving the current
Riciplay handoff. Migrate both producer and reader together; do not change only
one side's paths. The frozen CLI requires an addon refresh for the new persistence
helpers even when package installation alone succeeds.

The manifest contains package version and SHA-256 hashes for the three deployed
addon resources plus their canonical scope/runtime dependencies. Consumers should
compare the actual installed resources with their deployed copy. A manually
synchronized generation number alone can leave dependency bug fixes unapplied.

Refresh a complete deployment atomically before starting a new owned proxy. Never
overwrite files being used by another session or discard recovery ownership on a
partial deployment. Riciplay CLI v1.9.6's frozen checkout is not changed by this
dependency release; its release session must adapt and recertify independently.

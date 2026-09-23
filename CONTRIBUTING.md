# Contributing to MiniProxy

Thanks for helping make MiniProxy better! 🎉 MiniProxy is a small, focused
tool: an interception proxy for authorized security research with a terminal
UI (Textual), a web dashboard (Flask), and a shared SQLite capture DB.

## Ways to contribute

- **Bug reports** — wrong capture data, crashes, dashboard/API errors.
- **Docs** — anything that took you longer than it should have.
- **Tests** — the suite lives in `tests/` (pytest); coverage gaps welcome.
- **Features** — please open an issue first so we can agree on scope.

## Getting started

Requires Python 3.10+ and git.

```bash
git clone https://github.com/Zaidux/miniproxy
cd miniproxy
python -m venv .venv && source .venv/bin/activate
pip install -e ".[dev]"      # runtime deps + pytest, pytest-timeout
pip install mitmproxy        # provides mitmdump (capture engine)
pytest                       # run the test suite
```

Run any module directly for manual testing:

```bash
PYTHONPATH=src python -m miniproxy start        # proxy + dashboard
PYTHONPATH=src python -m miniproxy tui          # terminal UI
PYTHONPATH=src python -m miniproxy dashboard    # web UI in the foreground
```

## How we work

- **Tests are required** for bug fixes and features. If you fix a bug, add a
  regression test that fails without your fix. The suite must stay green:
  `pytest` (CI runs it on Linux/macOS × Python 3.10/3.12, plus a
  `node --check` syntax check on the dashboard's script block).
- **Keep PRs focused.** One feature or fix per PR; unrelated refactors go in
  their own PR.
- **Match the code style** of the file you're touching: small focused
  modules, module docstrings explaining *why* (several capture the history of
  a bug), type hints, `# ── section ──` banners.
- **Security-sensitive areas** (`app.py` auth/exports, `db.py` capture hot
  path, `server.py` process management) get extra scrutiny — read the
  comments there before changing behavior, and never weaken defaults (the
  dashboard binds loopback by default; that's deliberate).
- **Commit messages** are short and imperative, describing the *why*:
  `Harden dashboard, add exports + filters and committed test suite`.
- **No capture data in PRs.** Real captures contain tokens and personal
  data — sanitize any log output, screenshots, or HAR files you attach.

## Branching & PRs

1. Fork / branch from `main`.
2. Make your change with tests.
3. `pytest && python -m compileall -q src/miniproxy` locally.
4. Open a PR describing what changed and why; link the issue it fixes.

CI must pass before review. A maintainer will respond as time allows — this
is a side project.

## Reporting bugs

Use the **Bug report** issue template. For vulnerabilities, follow
[SECURITY.md](SECURITY.md) (private disclosure — do not open a public issue).

## License

By contributing, you agree your contributions are licensed under the MIT
License that covers the project.

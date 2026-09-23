---
name: Bug report
about: Something captured wrong, crashed, or misbehaved
title: ''
labels: bug
assignees: ''
---

**What happened?**
A clear description of the bug. What did you expect to happen instead?

**How to reproduce**
Steps (commands, config, URLs) that reliably trigger it:

```bash
# e.g.
miniproxy start --scope '*.example.com'
curl -x http://127.0.0.1:8080 https://example.com
```

**Environment (please complete):**
- OS:
- Python version (`python3 --version`):
- MiniProxy version (`miniproxy --version` or `pip show riciplay-miniproxy`):
- mitmproxy version (`mitmdump --version`):
- Where it happens: [ ] proxy/capture [ ] TUI [ ] web dashboard [ ] CLI [ ] npm install

**Logs / output**
Any traceback, console output, or dashboard response. **Sanitize captures**
(they contain tokens, cookies, and personal data) — replace hosts/headers
with placeholders.

**Additional context**
Anything else: config files, DB state, screenshots of the UI.

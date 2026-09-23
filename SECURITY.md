# Security Policy

## Supported versions

MiniProxy is a fast-moving pre-1.0 project. Only the **latest tagged release**
on PyPI (`riciplay-miniproxy`) and the tip of `main` receive security fixes.
Please always update before reporting:

```bash
pip install --upgrade riciplay-miniproxy
```

## Reporting a vulnerability

**Do not open a public GitHub issue for security reports.**

1. Use GitHub's **Private vulnerability reporting**:
   <https://github.com/Zaidux/miniproxy/security/advisories/new>
   (Security tab → Report a vulnerability).
2. Include: affected version/commit, a minimal reproduction (command line,
   config, capture), and your assessment of impact.
3. You will get an acknowledgment within **7 days**. We aim to ship a fix or
   a mitigation within **30 days** for high-severity issues, and will publish
   an advisory + changelog entry once a fixed release is out.

If you cannot use GitHub's private reporting, open a public issue asking for a
private contact channel — never include exploit details in the public issue.

## Responsible use — read this first

MiniProxy is an **interception proxy for authorized security testing** — the
same category of tool as mitmproxy, Burp Suite, and ZAP. It captures the
HTTP(S) traffic of whatever you point it at, including credentials, cookies,
session tokens, and personal data.

- Only intercept traffic to systems **you own or have explicit written
  permission to test** (your own apps, bug-bounty programs you've enrolled in,
  lab environments).
- Captures are stored **unencrypted** in SQLite (`~/.miniproxy/proxy.db` by
  default) and shown in the dashboard. Treat the DB and the dashboard URL as
  sensitive: don't expose them, don't commit them, delete them when done.
- Never point MiniProxy at systems you don't control, use it to intercept
  other people's traffic without consent, or rely on it to protect data.
- Nothing in this policy is legal advice — you are responsible for complying
  with the laws and program rules that apply where you use it.

## Scope

The following are in scope for security reports:

- The Python package (`src/miniproxy/**`): the capture addon, Flask dashboard,
  process manager, TUI, CLI.
- The npm launcher (`bin/`, `scripts/`) and its postinstall behavior.
- The packaged web dashboard (`src/miniproxy/templates/index.html`): XSS in
  rendered captures, auth bypasses, unsafe exports.

Known/accepted limitations (not vulnerabilities, but reports with a concrete
attack beyond these are welcome):

- The dashboard is a **lab tool**. Binding it beyond loopback
  (`--dashboard-host 0.0.0.0`) exposes captures to anyone who can reach the
  port; the optional `--dashboard-token` gates mutating endpoints but read
  endpoints (log listing, detail, exports) stay open by design.
- Captured bodies are stored truncated but otherwise unencrypted.
- The dashboard does not defend against hostile content *in* captures beyond
  the escaping applied when rendering; don't point MiniProxy at attacker-
  controlled sites you aren't authorized to test.

## Safe-harbor

We will consider good-faith research against your own local MiniProxy
instance to be authorized, won't pursue action for accidental, in-scope
findings reported privately, and will credit reporters in the changelog
unless they prefer anonymity.

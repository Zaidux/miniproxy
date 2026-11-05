#!/usr/bin/env node
// MiniProxy npm postinstall — installs the Python package from PyPI.
//
// This npm package is a thin launcher; the real implementation is the
// Python package `riciplay-miniproxy`. If it is not importable, pip
// install it. Failures are warnings, not errors: the user may be
// installing without network access or managing Python themselves.

const { spawnSync } = require('child_process');
const { target, candidates, check, supportedPython } = require('./runtime');

console.log('\n🔌 Installing MiniProxy (HTTP/S interception proxy)...\n');

try {
  const all = candidates();
  if (all.some(python => check(python))) {
    console.log(`✓ Matching MiniProxy ${target} and safe proxy dependencies found.`);
  } else {
    const python = all.find(p => supportedPython(p));
    if (!python) throw new Error('Python 3.12+ not found');
    // Do not mutate an overlapping install: uninstalling either distribution
    // removes files owned by the other. Operators must migrate explicitly.
    const overlap = spawnSync(python, ['-c',
      'from importlib.metadata import version,PackageNotFoundError\ntry: version("mitmproxy")\nexcept PackageNotFoundError: raise SystemExit(0)\nraise SystemExit(1)'],
      { timeout: 10000, stdio: 'ignore' });
    if (overlap.status !== 0) throw new Error('Upstream mitmproxy detected or could not be checked; use a fresh venv');
    const install = spawnSync(python, ['-m', 'pip', 'install', '--upgrade', `riciplay-miniproxy==${target}`],
      { stdio: 'inherit' });
    if (install.status !== 0 || !check(python)) throw new Error('Install failed or runtime verification failed');
    console.log(`✓ Installed and verified MiniProxy ${target}.`);
  }
} catch (err) {
  console.warn(
    `\n⚠ Could not install the Python package automatically (${err.message}).\n` +
    '  MiniProxy needs Python 3.12+ and a non-overlapping fork environment.\n' +
    `  In a fresh venv: python -m pip install riciplay-miniproxy==${target}\n` +
    '  Set MINIPROXY_PYTHON to that environment’s Python executable.\n'
  );
}

console.log('\nUsage: miniproxy start --port 8080   # then miniproxy dashboard\n');

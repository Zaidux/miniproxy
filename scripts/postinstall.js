#!/usr/bin/env node
// MiniProxy npm postinstall — installs the Python package from PyPI.
//
// This npm package is a thin launcher; the real implementation is the
// Python package `riciplay-miniproxy`. If it is not importable, pip
// install it. Failures are warnings, not errors: the user may be
// installing without network access or managing Python themselves.

const { execSync, spawnSync } = require('child_process');
const os = require('os');

console.log('\n🔌 Installing MiniProxy (HTTP/S interception proxy)...\n');

const isWin = os.platform() === 'win32';
const python = isWin ? 'python' : 'python3';
const pip = isWin ? 'pip' : 'pip3';

function hasCommand(cmd) {
  try {
    execSync(`${cmd} --version`, { stdio: 'ignore' });
    return true;
  } catch {
    return false;
  }
}

try {
  const probe = spawnSync(python, ['-c', 'import miniproxy'], { stdio: 'ignore' });
  if (probe.status === 0) {
    console.log('✓ Python package `miniproxy` already importable.');
  } else {
    console.log('Installing riciplay-miniproxy from PyPI...');
    execSync(`${pip} install --upgrade riciplay-miniproxy`, { stdio: 'inherit' });
    console.log('✓ Installed riciplay-miniproxy.');
  }
} catch (err) {
  console.warn(
    `\n⚠ Could not install the Python package automatically (${err.message}).\n` +
    '  MiniProxy needs Python 3.10+ and mitmproxy. Install manually with:\n' +
    '    pip install riciplay-miniproxy\n'
  );
}

console.log('\nUsage: miniproxy start --port 8080   # then miniproxy dashboard\n');

const assert = require('assert');
const fs = require('fs');
const os = require('os');
const path = require('path');
const { spawnSync } = require('child_process');
const { target, ready, check, candidates } = require('../scripts/runtime');
const good = { miniproxy_version: target, python_version: [3, 12, 3],
  proxy_distribution: 'riciplay-mitmproxy', proxy_version: '12.3.1.1',
  upstream_mitmproxy_version: null, tornado_version: '6.6', proxy_dependencies_supported: true };
assert(ready(good));
for (const bad of [null, { ...good, miniproxy_version: '0.9.6' },
  { ...good, python_version: [3, 10, 2] }, { ...good, upstream_mitmproxy_version: '12.3.1' },
  { ...good, proxy_dependencies_supported: 'true' }, { ...good, proxy_dependencies_supported: false }]) {
  assert(!ready(bad));
}
assert(!check('fake', () => ({ status: 0, stdout: 'not json' })));
assert.deepStrictEqual(candidates({ MINIPROXY_PYTHON: '/venv path/python' }), ['/venv path/python']);
const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'miniproxy-launcher-'));
try {
  const python = path.join(dir, 'python');
  const trace = path.join(dir, 'args.json');
  fs.writeFileSync(python, `#!${process.execPath}\nconst fs=require('fs');\nconst args=process.argv.slice(2);\n` +
    `if(args.includes('launcher-info')) console.log(process.env.FAKE_INFO);\n` +
    `else fs.writeFileSync(process.env.TRACE,JSON.stringify(args));\n`, { mode: 0o700 });
  const launcher = path.join(__dirname, '../bin/miniproxy');
  const env = { ...process.env, MINIPROXY_PYTHON: python, TRACE: trace, FAKE_INFO: JSON.stringify(good) };
  let result = spawnSync(process.execPath, [launcher, 'status', 'arg with spaces'], { env, encoding: 'utf8' });
  assert.strictEqual(result.status, 0, result.stderr);
  assert.deepStrictEqual(JSON.parse(fs.readFileSync(trace)), ['-m', 'miniproxy', 'status', 'arg with spaces']);
  fs.unlinkSync(trace);
  result = spawnSync(process.execPath, [launcher, 'start'], {
    env: { ...env, FAKE_INFO: JSON.stringify({ ...good, upstream_mitmproxy_version: '12.3.1' }) }, encoding: 'utf8' });
  assert.strictEqual(result.status, 1);
  assert(!fs.existsSync(trace));
} finally {
  fs.rmSync(dir, { recursive: true, force: true });
}
console.log('MiniProxy launcher regression passed');

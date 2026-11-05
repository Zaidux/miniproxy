const { target } = require('./runtime');
const { spawnSync } = require('child_process');

async function main() {
  const test = spawnSync(process.execPath, [require('path').join(__dirname, '../tests/npm_launcher_test.js')],
    { stdio: 'inherit' });
  if (test.status !== 0) throw new Error('Launcher regression failed');
  const res = await fetch(`https://pypi.org/pypi/riciplay-miniproxy/${target}/json`);
  if (!res.ok) throw new Error(`Matching PyPI version ${target} is not publicly available`);
  const data = await res.json();
  if (data.info.version !== target || !data.urls.some(u => !u.yanked)) throw new Error('PyPI release is unavailable/yanked');
  if (!(data.info.requires_dist || []).some(r => /^riciplay-mitmproxy\s*==\s*12\.3\.1\.1$/.test(r))) {
    throw new Error('Public Python metadata does not use the validated fork');
  }
}

main().catch(err => { console.error(`Publication held: ${err.message}`); process.exitCode = 1; });

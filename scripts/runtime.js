const { spawnSync } = require('child_process');
const target = require('../package.json').version;

function ready(info) {
  return info && info.miniproxy_version === target &&
    Array.isArray(info.python_version) && info.python_version.length === 3 &&
    info.python_version.every(n => Number.isSafeInteger(n) && n >= 0) &&
    info.python_version[0] === 3 && info.python_version[1] >= 12 &&
    info.proxy_distribution === 'riciplay-mitmproxy' &&
    typeof info.proxy_version === 'string' && typeof info.tornado_version === 'string' &&
    info.upstream_mitmproxy_version === null && info.proxy_dependencies_supported === true;
}

function candidates(env = process.env) {
  return env.MINIPROXY_PYTHON ? [env.MINIPROXY_PYTHON] :
    ['python3', 'python3.15', 'python3.14', 'python3.13', 'python3.12', 'python'];
}

function check(python, run = spawnSync) {
  try {
    const p = run(python, ['-m', 'miniproxy', 'launcher-info'],
      { encoding: 'utf8', timeout: 20000, maxBuffer: 65536 });
    return p.status === 0 && ready(JSON.parse(p.stdout));
  } catch { return false; }
}

function supportedPython(python, run = spawnSync) {
  try {
    const p = run(python, ['-c', 'import sys; sys.exit(0 if sys.version_info >= (3,12) else 1)'],
      { encoding: 'utf8', timeout: 10000, maxBuffer: 65536 });
    return p.status === 0;
  } catch { return false; }
}

module.exports = { target, ready, candidates, check, supportedPython };

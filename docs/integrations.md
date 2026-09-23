# Integrations

MiniProxy captures any HTTP client you point at it. The proxy listens on
`http://127.0.0.1:8080` by default.

## Command line

| Tool | How |
|------|-----|
| curl | `curl -x http://127.0.0.1:8080 https://example.com` |
| wget | `wget -e use_proxy=yes -e http_proxy=http://127.0.0.1:8080 https://example.com` |
| httpie | `http --proxy=http:http://127.0.0.1:8080 example.com` |
| git | `git -c http.proxy=http://127.0.0.1:8080 clone https://github.com/…` |

For HTTPS bodies add `--cacert ~/.mitmproxy/mitmproxy-ca-cert.pem` (curl)
or set `GIT_SSL_CAINFO` (git).

## Environment variables (whole shell)

Most Unix tools honor the standard proxy variables:

```bash
export http_proxy=http://127.0.0.1:8080
export https_proxy=http://127.0.0.1:8080
export HTTP_PROXY=$http_proxy HTTPS_PROXY=$https_proxy
export NO_PROXY=localhost,127.0.0.1
```

Unset them when you're done (`unset http_proxy https_proxy …`) or they'll
route everything — including MiniProxy's own dashboard requests — through
the proxy.

## Language runtimes

### Python (requests, pip, httpx)

```bash
export REQUESTS_CA_BUNDLE=~/.mitmproxy/mitmproxy-ca-cert.pem
export https_proxy=http://127.0.0.1:8080
pip install requests                  # captured
python -c "import requests; print(requests.get('https://api.github.com/zen').text)"
```

In code, pass explicitly instead of env vars:

```python
proxies = {"http": "http://127.0.0.1:8080", "https": "http://127.0.0.1:8080"}
# requests:
requests.get(url, proxies=proxies, verify="~/.mitmproxy/mitmproxy-ca-cert.pem")
```

### Node / npm

```bash
export HTTPS_PROXY=http://127.0.0.1:8080
export NODE_EXTRA_CA_CERTS=~/.mitmproxy/mitmproxy-ca-cert.pem
npm install            # captured (npm honors HTTPS_PROXY)
node fetch-script.js   # captured if your client honors proxy env / config
```

Node's `fetch`/undici needs an explicit ProxyAgent; axios honors
`HTTPS_PROXY` + `NODE_EXTRA_CA_CERTS` out of the box.

## Browsers

| Browser | Steps |
|---------|-------|
| Firefox | Settings → Network Settings → Manual proxy → HTTP `127.0.0.1:8080`, check "also use for HTTPS" |
| Chrome (system) | OS proxy settings (see below) |
| Chrome (isolated) | `google-chrome --proxy-server=http://127.0.0.1:8080 --user-data-dir=/tmp/proxy-profile` |

Import `~/.mitmproxy/mitmproxy-ca-cert.pem` into the browser (or OS) trust
store to read HTTPS bodies.

## Mobile devices

1. Start the proxy with `0.0.0.0` exposure so the phone can reach it:
   `mitmdump -s $(python3 -c "import miniproxy.addon, pathlib; print(pathlib.Path(miniproxy.addon.__file__).parent / 'proxy.py')") --set block_global=false --listen-port 8080`
2. Phone Wi-Fi → manual proxy → your computer's IP, port 8080.
3. Phone browser → `http://mitm.it` → install the CA for Android/iOS.

Watch everything from the Web UI on your desktop. To open the dashboard to
the phone too: `miniproxy start --dashboard-host 0.0.0.0 --dashboard-token s3cret`
(the token gates state-changing actions; the UI prompts for it once).

## Chaining with other proxies

Behind a corporate proxy or another interception tool? Add an upstream:

```bash
miniproxy start --no-dashboard   # then restart mitmdump manually with:
mitmdump -s <addon.py> --mode upstream:http://corporate-proxy:3128 --listen-port 8080
```

To hand captured requests to Burp/ZAP, copy them as curl (`c` in the TUI,
**Copy curl** in the Web UI) and replay through the other tool, or point
the other tool *at* MiniProxy as its upstream.

## Docker

Capture a container's traffic:

```bash
docker run --rm \
  -e HTTPS_PROXY=http://host.docker.internal:8080 \
  -e HTTP_PROXY=http://host.docker.internal:8080 \
  -e NODE_EXTRA_CA_CERTS=/certs/ca.pem \
  -v ~/.mitmproxy:/certs:ro \
  my-image
```

(Linux: add `--add-host=host.docker.internal:host-gateway`.)

## CI / headless capture

```bash
miniproxy start --no-dashboard &
export https_proxy=http://127.0.0.1:8080 REQUESTS_CA_BUNDLE=~/.miniproxy/mitmproxy-ca-cert.pem
pytest ./my-e2e-tests
miniproxy log --limit 200 > capture.txt
miniproxy stop
```

The `log`/`send`/`tui` commands are DB readers — they work on any machine
where you can copy the `proxy.db` file, which makes post-mortems easy:

```bash
scp server:~/.miniproxy/proxy.db ./lab.db
MINIPROXY_DB_PATH=./lab.db miniproxy tui   # inspect locally
```

(Or set `MINIPROXY_DB_PATH` in your shell profile / CI secrets.)

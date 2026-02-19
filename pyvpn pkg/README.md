# PyVPN

An importable Python VPN library designed to drop into any web scraping project.

## Install

```bash
pip install ./pyvpn               # core only
pip install "./pyvpn[scraping]"   # + requests + httpx
```

## Quickstart

```python
from pyvpn import VPNClient

with VPNClient(
    server="203.0.113.42",
    cert="certs/client.crt",
    key="certs/client.key",
    ca="certs/ca.crt",
) as vpn:
    session = vpn.requests_session()
    print(session.get("https://httpbin.org/ip").json())
```

The tunnel runs in a background thread — your code runs normally in the foreground.

## Generate certificates

```bash
python3 -m pyvpn.certs --out-dir ./certs --server-ip 203.0.113.42
```

Or from Python:

```python
from pyvpn import generate_certs
certs = generate_certs(out_dir="./certs", server_ips=["203.0.113.42"])
```

## Scraping integrations

```python
with VPNClient(...) as vpn:
    # requests
    session = vpn.requests_session(headers={"User-Agent": "MyBot/1.0"})

    # httpx (sync)
    with vpn.httpx_client() as client:
        r = client.get("https://example.com")

    # httpx (async)
    async with vpn.httpx_async_client() as client:
        r = await client.get("https://example.com")

    # Playwright
    from playwright.sync_api import sync_playwright
    with sync_playwright() as p:
        browser = p.chromium.launch(**vpn.playwright_launch_args())
```

## Load certs from env vars (Docker / CI)

```python
import os
from pyvpn import VPNClient

with VPNClient(
    server=os.environ["PYVPN_SERVER"],
    cert_pem=os.environ["PYVPN_CERT"],
    key_pem=os.environ["PYVPN_KEY"],
    ca_pem=os.environ["PYVPN_CA"],
) as vpn:
    ...
```

## CLI

```bash
# Start the server
sudo pyvpn-server --cert certs/server.crt --key certs/server.key --ca certs/ca.crt

# Start the client
sudo pyvpn-client --server 203.0.113.42 --cert certs/client.crt --key certs/client.key --ca certs/ca.crt

# Generate certificates
pyvpn-gencerts --out-dir ./certs --server-ip 203.0.113.42
```

## Requirements

- Linux (requires `/dev/net/tun`)
- Python 3.8+
- Root/sudo for tunnel creation
- `pip install cryptography`

## Security features

- Mutual X.509 certificate authentication
- X25519 ECDH ephemeral key exchange (perfect forward secrecy)
- AES-256-GCM encryption
- Replay attack protection (64-bit sequence numbers + sliding window)
- Keepalive / dead-peer detection
- Auto-reconnect with exponential backoff

## License

MIT

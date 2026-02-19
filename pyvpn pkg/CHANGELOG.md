# Changelog

All notable changes to PyVPN are documented here.
Format follows [Keep a Changelog](https://keepachangelog.com/en/1.0.0/).

---

## [2.0.0] — 2026-02-19

### Added
- `VPNClient` and `VPNServer` classes — importable, context-manager API
- Background-thread tunnel loop — VPN runs while your scraping code runs normally
- `vpn.requests_session()` — pre-configured `requests.Session`
- `vpn.httpx_client()` — pre-configured `httpx.Client` (sync)
- `vpn.httpx_async_client()` — pre-configured `httpx.AsyncClient`
- `vpn.playwright_launch_args()` — Playwright browser launch dict
- `cert_pem` / `key_pem` / `ca_pem` string params — load certs from env vars or secret managers without touching the filesystem
- `generate_certs()` importable function — create CA + server + client certs from Python
- `python3 -m pyvpn` entry point
- `pyvpn-server`, `pyvpn-client`, `pyvpn-gencerts` CLI scripts
- X25519 ECDH ephemeral key exchange → perfect forward secrecy
- Mutual X.509 certificate authentication (client and server both verified)
- AES-256-GCM packet encryption with per-packet random nonce
- 64-bit sequence numbers + sliding-window replay attack protection
- Keepalive heartbeat every 15 s, dead-peer timeout at 45 s
- Auto-reconnect with exponential backoff (2 s → 60 s cap)
- `py.typed` marker for mypy/pyright support
- `examples/scraping_examples.py` covering requests, httpx, BeautifulSoup, Playwright, Scrapy, env-var certs

### Changed
- Replaced pre-shared key model with certificate-based mutual auth
- Tunnel logic moved from standalone scripts into importable `VPNClient`/`VPNServer` classes
- Shared crypto/TUN primitives extracted to `pyvpn._core`

---

## [1.0.0] — 2026-02-18

### Added
- Initial standalone `vpn_server.py` and `vpn_client.py` scripts
- AES-256-GCM encryption with pre-shared key
- TUN interface creation and IP routing
- `--route-all` flag for full traffic tunnelling

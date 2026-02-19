"""
python3 -m pyvpn
Prints package info and available CLI commands.
"""

import sys


def main():
    from pyvpn import __version__

    print(f"""
PyVPN v{__version__} — importable Python VPN for web scraping

Usage:
  python3 -m pyvpn.certs    [--out-dir ./certs] [--server-ip <ip>]
  python3 -m pyvpn.server   --cert <path> --key <path> --ca <path>
  python3 -m pyvpn.client   --server <ip> --cert <path> --key <path> --ca <path>

Or after `pip install pyvpn`:
  pyvpn-gencerts  --out-dir ./certs --server-ip <ip>
  pyvpn-server    --cert certs/server.crt --key certs/server.key --ca certs/ca.crt
  pyvpn-client    --server <ip> --cert certs/client.crt --key certs/client.key --ca certs/ca.crt

Python API:
  from pyvpn import VPNClient
  with VPNClient(server="<ip>", cert="...", key="...", ca="...") as vpn:
      session = vpn.requests_session()
      print(session.get("https://httpbin.org/ip").json())

See examples/ for requests, httpx, Playwright, Scrapy, and async usage.
""")


if __name__ == "__main__":
    main()

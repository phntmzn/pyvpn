"""
PyVPN — importable VPN library
==============================
Quick start for web scraping:

    from pyvpn import VPNClient

    with VPNClient(
        server="203.0.113.42",
        cert="certs/client.crt",
        key="certs/client.key",
        ca="certs/ca.crt",
    ) as vpn:
        # All traffic on this machine now routes through the VPN.
        # Use requests, httpx, playwright, selenium — anything.
        import requests
        r = requests.get("https://httpbin.org/ip")
        print(r.json())   # Shows VPN server's IP

Or use the built-in scraping helpers:

    with VPNClient(...) as vpn:
        session = vpn.requests_session()
        r = session.get("https://example.com")
"""

from .client import VPNClient
from .server import VPNServer
from .certs import generate_certs, load_cert, load_privkey

__all__ = ["VPNClient", "VPNServer", "generate_certs", "load_cert", "load_privkey"]
__version__ = "2.0.0"

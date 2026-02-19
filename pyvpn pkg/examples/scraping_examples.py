"""
examples/scraping_examples.py
==============================
Demonstrates how to integrate PyVPN into web scraping projects.
All examples assume the VPN server is already running.

Run any example with:
    sudo python3 examples/scraping_examples.py
"""

# ─────────────────────────────────────────────────────────────────────────────
# Example 1 — requests (simplest usage)
# ─────────────────────────────────────────────────────────────────────────────

def example_requests():
    from pyvpn import VPNClient

    with VPNClient(
        server="203.0.113.42",
        cert="certs/client.crt",
        key="certs/client.key",
        ca="certs/ca.crt",
    ) as vpn:
        session = vpn.requests_session(headers={"User-Agent": "MyBot/1.0"})

        r = session.get("https://httpbin.org/ip")
        print("My IP through VPN:", r.json()["origin"])

        # Scrape multiple pages — session reuses the connection pool
        for url in ["https://httpbin.org/get", "https://httpbin.org/headers"]:
            r = session.get(url)
            print(url, "→", r.status_code)


# ─────────────────────────────────────────────────────────────────────────────
# Example 2 — httpx (sync)
# ─────────────────────────────────────────────────────────────────────────────

def example_httpx_sync():
    from pyvpn import VPNClient

    with VPNClient(
        server="203.0.113.42",
        cert="certs/client.crt",
        key="certs/client.key",
        ca="certs/ca.crt",
    ) as vpn:
        with vpn.httpx_client() as client:
            r = client.get("https://httpbin.org/ip")
            print("IP:", r.json()["origin"])


# ─────────────────────────────────────────────────────────────────────────────
# Example 3 — httpx (async)
# ─────────────────────────────────────────────────────────────────────────────

async def example_httpx_async():
    import asyncio
    from pyvpn import VPNClient

    with VPNClient(
        server="203.0.113.42",
        cert="certs/client.crt",
        key="certs/client.key",
        ca="certs/ca.crt",
    ) as vpn:
        async with vpn.httpx_async_client() as client:
            # Fetch multiple pages concurrently through the VPN
            urls = [
                "https://httpbin.org/ip",
                "https://httpbin.org/get",
                "https://httpbin.org/user-agent",
            ]
            responses = await asyncio.gather(*[client.get(u) for u in urls])
            for url, r in zip(urls, responses):
                print(f"{url}: {r.status_code}")


# ─────────────────────────────────────────────────────────────────────────────
# Example 4 — BeautifulSoup scraper
# ─────────────────────────────────────────────────────────────────────────────

def example_beautifulsoup():
    """
    pip install requests beautifulsoup4
    """
    from pyvpn import VPNClient
    from bs4 import BeautifulSoup

    with VPNClient(
        server="203.0.113.42",
        cert="certs/client.crt",
        key="certs/client.key",
        ca="certs/ca.crt",
    ) as vpn:
        session = vpn.requests_session()
        r = session.get("https://news.ycombinator.com")
        soup = BeautifulSoup(r.text, "html.parser")
        titles = soup.select(".titleline > a")
        for t in titles[:5]:
            print(t.text)


# ─────────────────────────────────────────────────────────────────────────────
# Example 5 — Playwright (headless browser)
# ─────────────────────────────────────────────────────────────────────────────

def example_playwright():
    """
    pip install playwright && playwright install chromium
    """
    from pyvpn import VPNClient
    from playwright.sync_api import sync_playwright

    with VPNClient(
        server="203.0.113.42",
        cert="certs/client.crt",
        key="certs/client.key",
        ca="certs/ca.crt",
    ) as vpn:
        with sync_playwright() as p:
            browser = p.chromium.launch(**vpn.playwright_launch_args())
            page = browser.new_page()
            page.goto("https://httpbin.org/ip")
            print("Browser IP:", page.locator("body").inner_text())
            browser.close()


# ─────────────────────────────────────────────────────────────────────────────
# Example 6 — Scrapy (spider integration)
# ─────────────────────────────────────────────────────────────────────────────

def example_scrapy_middleware():
    """
    Drop this middleware into your Scrapy project's middlewares.py.
    It starts the VPN before the spider runs and stops it after.

    In settings.py add:
        DOWNLOADER_MIDDLEWARES = {
            'myproject.middlewares.VPNMiddleware': 100,
        }
    """
    # middlewares.py
    middleware_code = '''
from pyvpn import VPNClient

class VPNMiddleware:
    def __init__(self):
        self.vpn = VPNClient(
            server="203.0.113.42",
            cert="certs/client.crt",
            key="certs/client.key",
            ca="certs/ca.crt",
        )

    @classmethod
    def from_crawler(cls, crawler):
        return cls()

    def spider_opened(self, spider):
        self.vpn.connect()
        spider.logger.info("VPN tunnel established")

    def spider_closed(self, spider):
        self.vpn.disconnect()
        spider.logger.info("VPN tunnel closed")
    '''
    print(middleware_code)


# ─────────────────────────────────────────────────────────────────────────────
# Example 7 — Load certs from environment variables (no files on disk)
# ─────────────────────────────────────────────────────────────────────────────

def example_env_certs():
    """
    Store certificates in environment variables (useful for Docker / CI).
    Export them like:
        export PYVPN_CERT="$(cat certs/client.crt)"
        export PYVPN_KEY="$(cat certs/client.key)"
        export PYVPN_CA="$(cat certs/ca.crt)"
    """
    import os
    from pyvpn import VPNClient

    with VPNClient(
        server=os.environ["PYVPN_SERVER"],
        cert_pem=os.environ["PYVPN_CERT"],   # PEM string, not file path
        key_pem=os.environ["PYVPN_KEY"],
        ca_pem=os.environ["PYVPN_CA"],
    ) as vpn:
        session = vpn.requests_session()
        print(session.get("https://httpbin.org/ip").json())


# ─────────────────────────────────────────────────────────────────────────────
# Example 8 — Generate certs programmatically (no CLI needed)
# ─────────────────────────────────────────────────────────────────────────────

def example_generate_certs():
    """
    Generate certs entirely in Python — useful for testing or bootstrapping.
    Must run as root (needed to write to /dev/net/tun later).
    """
    from pyvpn import generate_certs, VPNClient

    # Generates files in ./certs/ AND returns PEM strings
    certs = generate_certs(
        out_dir="./certs",
        server_ips=["203.0.113.42"],
    )

    # Pass PEM strings directly — no file paths needed
    vpn = VPNClient(
        server="203.0.113.42",
        cert_pem=certs["client_crt"],
        key_pem=certs["client_key"],
        ca_pem=certs["ca_crt"],
    )
    print("Certs generated. VPN client ready (server must also be restarted with new certs).")


# ─────────────────────────────────────────────────────────────────────────────

if __name__ == "__main__":
    import asyncio

    print("=== Example 1: requests ===")
    example_requests()

    print("\n=== Example 2: httpx sync ===")
    example_httpx_sync()

    print("\n=== Example 3: httpx async ===")
    asyncio.run(example_httpx_async())

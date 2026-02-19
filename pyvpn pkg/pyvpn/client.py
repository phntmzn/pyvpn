"""
pyvpn.client — VPNClient
========================
Importable VPN client designed to be embedded in any Python project.

Usage
-----
Basic (context manager):

    from pyvpn import VPNClient

    with VPNClient(
        server="203.0.113.42",
        cert="certs/client.crt",
        key="certs/client.key",
        ca="certs/ca.crt",
    ) as vpn:
        import requests
        print(requests.get("https://httpbin.org/ip").json())

Built-in scraping helpers:

    with VPNClient(...) as vpn:
        # requests.Session pre-configured with VPN-friendly settings
        session = vpn.requests_session(headers={"User-Agent": "MyBot/1.0"})
        r = session.get("https://example.com")

        # httpx.Client (async or sync)
        async with vpn.httpx_client() as client:
            r = await client.get("https://example.com")

Manual (non-context-manager):

    vpn = VPNClient(server=..., cert=..., key=..., ca=...)
    vpn.connect()
    # ... do work ...
    vpn.disconnect()

Programmatic certificate loading (no files needed):

    from pyvpn import VPNClient
    vpn = VPNClient(
        server="203.0.113.42",
        cert_pem=open("certs/client.crt").read(),
        key_pem=open("certs/client.key").read(),
        ca_pem=open("certs/ca.crt").read(),
    )
"""

import os
import sys
import socket
import select
import logging
import threading
import time
from typing import Optional

from ._core import (
    BUFFER_SIZE, MTU,
    TYPE_DATA, TYPE_HANDSHAKE, TYPE_KEEPALIVE, TYPE_HANDSHAKE_RESPONSE,
    KEEPALIVE_INTERVAL, PEER_TIMEOUT, RECONNECT_INITIAL, RECONNECT_MAX,
    create_tun, configure_interface, add_default_routes, remove_default_routes,
    load_cert, load_privkey,
    derive_session_key, encrypt_packet, decrypt_packet,
    ReplayWindow, build_hello, verify_hello,
)
from cryptography.x509 import load_pem_x509_certificate
from cryptography.hazmat.primitives import serialization

log = logging.getLogger(__name__)


class VPNClient:
    """
    Encrypted VPN tunnel client.

    Can be used as a context manager or manually via connect()/disconnect().
    The tunnel runs in a background daemon thread so your scraping code runs
    normally in the foreground.

    Parameters
    ----------
    server : str
        VPN server hostname or IP address.
    port : int
        UDP port the server is listening on (default: 5000).
    cert : str, optional
        Path to client certificate PEM file.
    key : str, optional
        Path to client private key PEM file.
    ca : str, optional
        Path to CA certificate PEM file.
    cert_pem / key_pem / ca_pem : str, optional
        PEM contents as strings — use instead of file paths if loading from
        a secret manager, environment variable, database, etc.
    local_ip : str
        IP address assigned to the local TUN interface (default: 10.8.0.2).
    server_tun_ip : str
        IP address of the server's TUN interface (default: 10.8.0.1).
    route_all : bool
        If True, all internet traffic is routed through the VPN (default: True).
        Set to False to only route 10.8.0.0/24 through the tunnel.
    tun_name : str
        Name of the TUN interface to create (default: "tun0").
    connect_timeout : float
        Seconds to wait for the handshake to complete (default: 10).
    """

    def __init__(
        self,
        server: str,
        port: int = 5000,
        *,
        # File-path based cert loading
        cert: Optional[str] = None,
        key: Optional[str] = None,
        ca: Optional[str] = None,
        # In-memory PEM string based cert loading
        cert_pem: Optional[str] = None,
        key_pem: Optional[str] = None,
        ca_pem: Optional[str] = None,
        # Tunnel options
        local_ip: str = "10.8.0.2",
        server_tun_ip: str = "10.8.0.1",
        route_all: bool = True,
        tun_name: str = "tun0",
        connect_timeout: float = 10.0,
    ):
        self.server          = server
        self.port            = port
        self.local_ip        = local_ip
        self.server_tun_ip   = server_tun_ip
        self.route_all       = route_all
        self.tun_name        = tun_name
        self.connect_timeout = connect_timeout

        # Load certificates
        self._client_cert = (
            load_pem_x509_certificate(cert_pem.encode()) if cert_pem
            else load_cert(cert)
        )
        self._client_key = (
            serialization.load_pem_private_key(key_pem.encode(), password=None) if key_pem
            else load_privkey(key)
        )
        self._ca_cert = (
            load_pem_x509_certificate(ca_pem.encode()) if ca_pem
            else load_cert(ca)
        )

        # Internal state
        self._tun           = None
        self._thread        = None
        self._stop_event    = threading.Event()
        self._connected     = threading.Event()
        self._routes_added  = False
        self._connect_error: Optional[Exception] = None

    # ── Public API ─────────────────────────────────────────────────────────────

    def connect(self, wait: bool = True, timeout: Optional[float] = None) -> "VPNClient":
        """
        Start the VPN tunnel in a background thread.

        Parameters
        ----------
        wait : bool
            Block until the tunnel is established (default: True).
        timeout : float, optional
            How long to wait for the tunnel to come up. Defaults to
            connect_timeout passed to the constructor.

        Raises
        ------
        PermissionError
            If not running as root.
        RuntimeError
            If the tunnel fails to establish within timeout.
        """
        if os.geteuid() != 0:
            raise PermissionError("VPNClient requires root privileges (run with sudo)")

        self._stop_event.clear()
        self._connected.clear()
        self._connect_error = None

        # Create TUN before thread so errors surface immediately
        self._tun = create_tun(self.tun_name)
        configure_interface(self.tun_name, self.local_ip, MTU)

        self._thread = threading.Thread(target=self._run, daemon=True, name="pyvpn-client")
        self._thread.start()

        if wait:
            deadline = timeout or self.connect_timeout * 3
            if not self._connected.wait(timeout=deadline):
                self._stop_event.set()
                err = self._connect_error
                raise RuntimeError(
                    f"VPN tunnel failed to establish within {deadline}s"
                    + (f": {err}" if err else "")
                )
            if self._connect_error:
                raise RuntimeError(f"VPN handshake failed: {self._connect_error}")

        return self

    def disconnect(self):
        """Tear down the VPN tunnel and restore routing."""
        self._stop_event.set()
        if self._thread:
            self._thread.join(timeout=5)
        if self._routes_added:
            remove_default_routes(self.server)
            self._routes_added = False
        if self._tun:
            try:
                self._tun.close()
            except Exception:
                pass
            self._tun = None
        log.info("VPN disconnected")

    @property
    def is_connected(self) -> bool:
        """True if the tunnel is currently established and alive."""
        return self._connected.is_set() and not self._stop_event.is_set()

    # ── Scraping helpers ───────────────────────────────────────────────────────

    def requests_session(self, headers: Optional[dict] = None, **kwargs):
        """
        Return a configured requests.Session that works through the VPN.

        Requires: pip install requests

        Parameters
        ----------
        headers : dict, optional
            Extra headers to set on every request (e.g. User-Agent).
        **kwargs
            Passed to requests.Session().

        Example
        -------
            with VPNClient(...) as vpn:
                s = vpn.requests_session(headers={"User-Agent": "MyBot/1.0"})
                r = s.get("https://example.com")
        """
        try:
            import requests
        except ImportError:
            raise ImportError("requests is not installed. Run: pip install requests")

        session = requests.Session(**kwargs)
        session.headers.update({
            "User-Agent": "Mozilla/5.0 (compatible; PyVPN-Scraper/2.0)",
        })
        if headers:
            session.headers.update(headers)

        # Sane scraping defaults
        adapter = requests.adapters.HTTPAdapter(
            max_retries=requests.adapters.Retry(
                total=3,
                backoff_factor=0.5,
                status_forcelist=[429, 500, 502, 503, 504],
            )
        )
        session.mount("http://", adapter)
        session.mount("https://", adapter)
        return session

    def httpx_client(self, headers: Optional[dict] = None, **kwargs):
        """
        Return a configured httpx.Client (sync) that works through the VPN.

        Requires: pip install httpx

        Example
        -------
            with VPNClient(...) as vpn:
                with vpn.httpx_client() as client:
                    r = client.get("https://example.com")
        """
        try:
            import httpx
        except ImportError:
            raise ImportError("httpx is not installed. Run: pip install httpx")

        default_headers = {"User-Agent": "Mozilla/5.0 (compatible; PyVPN-Scraper/2.0)"}
        if headers:
            default_headers.update(headers)
        return httpx.Client(headers=default_headers, follow_redirects=True, **kwargs)

    def httpx_async_client(self, headers: Optional[dict] = None, **kwargs):
        """
        Return a configured httpx.AsyncClient that works through the VPN.

        Requires: pip install httpx

        Example
        -------
            with VPNClient(...) as vpn:
                async with vpn.httpx_async_client() as client:
                    r = await client.get("https://example.com")
        """
        try:
            import httpx
        except ImportError:
            raise ImportError("httpx is not installed. Run: pip install httpx")

        default_headers = {"User-Agent": "Mozilla/5.0 (compatible; PyVPN-Scraper/2.0)"}
        if headers:
            default_headers.update(headers)
        return httpx.AsyncClient(headers=default_headers, follow_redirects=True, **kwargs)

    def playwright_launch_args(self) -> dict:
        """
        Return keyword arguments to pass to playwright's browser.launch() so
        that the browser routes traffic through the VPN.

        Requires: pip install playwright && playwright install

        Example
        -------
            with VPNClient(...) as vpn:
                from playwright.sync_api import sync_playwright
                with sync_playwright() as p:
                    browser = p.chromium.launch(**vpn.playwright_launch_args())
                    page = browser.new_page()
                    page.goto("https://example.com")
        """
        return {
            # No proxy needed — the TUN interface handles routing at the OS level.
            # These args suppress GPU / sandbox warnings common in headless envs.
            "args": [
                "--no-sandbox",
                "--disable-gpu",
                "--disable-dev-shm-usage",
            ],
            "headless": True,
        }

    # ── Context manager ────────────────────────────────────────────────────────

    def __enter__(self) -> "VPNClient":
        self.connect()
        return self

    def __exit__(self, *_):
        self.disconnect()

    # ── Internal tunnel loop ───────────────────────────────────────────────────

    def _run(self):
        """Background thread: connect, forward packets, reconnect on failure."""
        server_addr     = (self.server, self.port)
        reconnect_delay = RECONNECT_INITIAL

        while not self._stop_event.is_set():
            sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)

            try:
                session_key = self._handshake(sock, server_addr)
            except Exception as e:
                self._connect_error = e
                log.error(f"Handshake failed: {e}")
                sock.close()
                if not self._connected.is_set():
                    # First connection — signal failure so connect() can raise
                    self._connected.set()
                    return
                _wait(self._stop_event, reconnect_delay)
                reconnect_delay = min(reconnect_delay * 2, RECONNECT_MAX)
                continue

            # Tunnel established
            self._connect_error = None
            reconnect_delay = RECONNECT_INITIAL

            if self.route_all and not self._routes_added:
                add_default_routes(self.server, self.server_tun_ip)
                self._routes_added = True

            self._connected.set()
            log.info(f"VPN tunnel established → {self.server}:{self.port}")

            # Forward packets until dead or stopped
            dropped = self._forward(sock, server_addr, session_key)
            sock.close()

            if self._stop_event.is_set():
                break

            if dropped:
                log.warning("Server went silent — reconnecting...")
                self._connected.clear()
                _wait(self._stop_event, reconnect_delay)
                reconnect_delay = min(reconnect_delay * 2, RECONNECT_MAX)

    def _handshake(self, sock: socket.socket, server_addr: tuple) -> bytes:
        """Perform mutual-auth ECDH handshake. Returns session_key bytes."""
        ecdh_priv, hello_payload = build_hello(self._client_cert, self._client_key)

        sock.sendto(TYPE_HANDSHAKE + hello_payload, server_addr)
        log.debug("ClientHello sent")

        sock.settimeout(self.connect_timeout)
        try:
            data, _ = sock.recvfrom(BUFFER_SIZE)
        except socket.timeout:
            raise TimeoutError(f"No response from {server_addr[0]}:{server_addr[1]} within {self.connect_timeout}s")
        finally:
            sock.settimeout(None)
            sock.setblocking(False)

        if data[:1] != TYPE_HANDSHAKE_RESPONSE:
            raise ValueError(f"Unexpected packet type during handshake: {data[:1].hex()}")

        peer_cert, peer_ecdh_pub = verify_hello(data[1:], self._ca_cert)
        log.info(f"Server cert verified: {peer_cert.subject.rfc4514_string()}")

        return derive_session_key(ecdh_priv, peer_ecdh_pub)

    def _forward(self, sock: socket.socket, server_addr: tuple, session_key: bytes) -> bool:
        """
        Packet forwarding loop.
        Returns True if we dropped due to peer timeout, False if gracefully stopped.
        """
        send_seq     = 0
        replay       = ReplayWindow()
        last_seen    = time.monotonic()
        last_ka_sent = time.monotonic()
        tun          = self._tun

        while not self._stop_event.is_set():
            now = time.monotonic()

            # Dead-peer detection
            if now - last_seen > PEER_TIMEOUT:
                return True  # signal reconnect

            # Keepalive
            if now - last_ka_sent >= KEEPALIVE_INTERVAL:
                try:
                    pkt = encrypt_packet(session_key, send_seq, TYPE_KEEPALIVE, b"")
                    send_seq += 1
                    sock.sendto(pkt, server_addr)
                except Exception:
                    pass
                last_ka_sent = now

            rlist, _, _ = select.select([tun, sock], [], [], KEEPALIVE_INTERVAL / 2)

            # TUN → Server
            if tun in rlist:
                try:
                    packet = tun.read(BUFFER_SIZE)
                    enc = encrypt_packet(session_key, send_seq, TYPE_DATA, packet)
                    send_seq += 1
                    sock.sendto(enc, server_addr)
                except Exception as e:
                    log.warning(f"Send error: {e}")

            # Server → TUN
            if sock in rlist:
                try:
                    data, _ = sock.recvfrom(BUFFER_SIZE + 256)
                except BlockingIOError:
                    continue

                try:
                    ptype, seq, payload = decrypt_packet(session_key, data)
                except Exception as e:
                    log.warning(f"Decrypt error: {e}")
                    continue

                if not replay.check_and_add(seq):
                    log.debug(f"Replayed packet seq={seq} dropped")
                    continue

                last_seen = time.monotonic()

                if ptype == TYPE_DATA:
                    try:
                        tun.write(payload)
                    except Exception as e:
                        log.warning(f"TUN write error: {e}")
                elif ptype == TYPE_KEEPALIVE:
                    log.debug("Keepalive from server")

        return False  # graceful stop


def _wait(stop_event: threading.Event, delay: float):
    """Sleep for delay seconds, waking early if stop_event is set."""
    stop_event.wait(timeout=delay)

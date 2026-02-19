"""
pyvpn.server — VPNServer
========================
Importable VPN server. Can run embedded in a larger Python application
or standalone from the command line.

Usage (embedded):

    from pyvpn import VPNServer

    with VPNServer(
        cert="certs/server.crt",
        key="certs/server.key",
        ca="certs/ca.crt",
    ):
        print("VPN server running, press Ctrl+C to stop")
        import time; time.sleep(float("inf"))

Usage (standalone CLI):

    python3 -m pyvpn.server --cert certs/server.crt --key certs/server.key --ca certs/ca.crt
"""

import os
import sys
import socket
import select
import logging
import threading
import time
import argparse
from typing import Optional

from ._core import (
    BUFFER_SIZE, MTU,
    TYPE_DATA, TYPE_HANDSHAKE, TYPE_KEEPALIVE,
    KEEPALIVE_INTERVAL, PEER_TIMEOUT,
    create_tun, configure_interface,
    load_cert, load_privkey,
    derive_session_key, encrypt_packet, decrypt_packet,
    ReplayWindow, build_hello, verify_hello,
    TYPE_HANDSHAKE_RESPONSE,
)
from cryptography.x509 import load_pem_x509_certificate
from cryptography.hazmat.primitives import serialization

log = logging.getLogger(__name__)


class _ClientSession:
    """Tracks per-client state on the server side."""
    def __init__(self, addr, session_key):
        self.addr        = addr
        self.session_key = session_key
        self.send_seq    = 0
        self.replay      = ReplayWindow()
        self.last_seen   = time.monotonic()

    def touch(self):
        self.last_seen = time.monotonic()

    def is_alive(self) -> bool:
        return (time.monotonic() - self.last_seen) < PEER_TIMEOUT

    def next_seq(self) -> int:
        seq = self.send_seq
        self.send_seq += 1
        return seq


class VPNServer:
    """
    Encrypted VPN tunnel server.

    Can be used as a context manager or manually via start()/stop().
    The server loop runs in a background daemon thread.

    Parameters
    ----------
    host : str
        Interface to bind to (default: "0.0.0.0").
    port : int
        UDP port to listen on (default: 5000).
    cert / key / ca : str
        Paths to server certificate, private key, and CA certificate PEM files.
    cert_pem / key_pem / ca_pem : str
        PEM contents as strings instead of file paths.
    tun_ip : str
        IP address for the server TUN interface (default: "10.8.0.1").
    tun_name : str
        Name of the TUN interface (default: "tun0").
    """

    def __init__(
        self,
        host: str = "0.0.0.0",
        port: int = 5000,
        *,
        cert: Optional[str] = None,
        key: Optional[str] = None,
        ca: Optional[str] = None,
        cert_pem: Optional[str] = None,
        key_pem: Optional[str] = None,
        ca_pem: Optional[str] = None,
        tun_ip: str = "10.8.0.1",
        tun_name: str = "tun0",
    ):
        self.host     = host
        self.port     = port
        self.tun_ip   = tun_ip
        self.tun_name = tun_name

        self._server_cert = (
            load_pem_x509_certificate(cert_pem.encode()) if cert_pem else load_cert(cert)
        )
        self._server_key = (
            serialization.load_pem_private_key(key_pem.encode(), password=None) if key_pem
            else load_privkey(key)
        )
        self._ca_cert = (
            load_pem_x509_certificate(ca_pem.encode()) if ca_pem else load_cert(ca)
        )

        self._tun        = None
        self._thread     = None
        self._stop_event = threading.Event()
        self._ready      = threading.Event()

    def start(self, wait: bool = True, timeout: float = 5.0) -> "VPNServer":
        """Start the server in a background thread."""
        if os.geteuid() != 0:
            raise PermissionError("VPNServer requires root privileges (run with sudo)")

        self._stop_event.clear()
        self._ready.clear()

        self._tun = create_tun(self.tun_name)
        configure_interface(self.tun_name, self.tun_ip, MTU)

        self._thread = threading.Thread(target=self._run, daemon=True, name="pyvpn-server")
        self._thread.start()

        if wait and not self._ready.wait(timeout=timeout):
            raise RuntimeError("VPN server failed to start within timeout")

        return self

    def stop(self):
        """Shut down the server and release resources."""
        self._stop_event.set()
        if self._thread:
            self._thread.join(timeout=5)
        if self._tun:
            try:
                self._tun.close()
            except Exception:
                pass
            self._tun = None
        log.info("VPN server stopped")

    def __enter__(self) -> "VPNServer":
        return self.start()

    def __exit__(self, *_):
        self.stop()

    def _handshake(self, sock, addr, data) -> Optional[_ClientSession]:
        """Process a ClientHello and respond with ServerHello. Returns session or None."""
        try:
            peer_cert, peer_ecdh_pub = verify_hello(data, self._ca_cert)
            log.info(f"Client cert verified: {peer_cert.subject.rfc4514_string()} from {addr}")

            ecdh_priv, hello_payload = build_hello(self._server_cert, self._server_key)
            sock.sendto(TYPE_HANDSHAKE_RESPONSE + hello_payload, addr)

            session_key = derive_session_key(ecdh_priv, peer_ecdh_pub)
            return _ClientSession(addr, session_key)
        except Exception as e:
            log.warning(f"Handshake rejected from {addr}: {e}")
            return None

    def _run(self):
        """Server event loop."""
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        sock.bind((self.host, self.port))
        sock.setblocking(False)
        log.info(f"VPN server listening on UDP {self.host}:{self.port}")
        self._ready.set()

        session: Optional[_ClientSession] = None
        last_ka = time.monotonic()
        tun     = self._tun

        try:
            while not self._stop_event.is_set():
                now = time.monotonic()

                # Keepalive / dead-peer detection
                if session:
                    if not session.is_alive():
                        log.warning(f"Client {session.addr} timed out")
                        session = None
                    elif now - last_ka >= KEEPALIVE_INTERVAL:
                        try:
                            pkt = encrypt_packet(
                                session.session_key, session.next_seq(), TYPE_KEEPALIVE, b""
                            )
                            sock.sendto(pkt, session.addr)
                        except Exception:
                            pass
                        last_ka = now

                rlist, _, _ = select.select([tun, sock], [], [], KEEPALIVE_INTERVAL / 2)

                # TUN → Client
                if tun in rlist:
                    packet = tun.read(BUFFER_SIZE)
                    if session:
                        try:
                            enc = encrypt_packet(
                                session.session_key, session.next_seq(), TYPE_DATA, packet
                            )
                            sock.sendto(enc, session.addr)
                        except Exception as e:
                            log.warning(f"Send error: {e}")

                # Client → TUN
                if sock in rlist:
                    try:
                        data, addr = sock.recvfrom(BUFFER_SIZE + 256)
                    except BlockingIOError:
                        continue

                    if data[:1] == TYPE_HANDSHAKE:
                        new = self._handshake(sock, addr, data[1:])
                        if new:
                            session = new
                            last_ka = time.monotonic()
                        continue

                    if session is None or addr != session.addr:
                        log.debug(f"Ignoring data from unknown {addr}")
                        continue

                    try:
                        ptype, seq, payload = decrypt_packet(session.session_key, data)
                    except Exception as e:
                        log.warning(f"Decrypt error from {addr}: {e}")
                        continue

                    if not session.replay.check_and_add(seq):
                        log.debug(f"Replayed packet seq={seq} from {addr} dropped")
                        continue

                    session.touch()

                    if ptype == TYPE_DATA:
                        tun.write(payload)
                    elif ptype == TYPE_KEEPALIVE:
                        pkt = encrypt_packet(
                            session.session_key, session.next_seq(), TYPE_KEEPALIVE, b""
                        )
                        sock.sendto(pkt, addr)

        finally:
            sock.close()


# ── CLI entry point ───────────────────────────────────────────────────────────

def _main():
    parser = argparse.ArgumentParser(description="PyVPN Server")
    parser.add_argument("--host",   default="0.0.0.0")
    parser.add_argument("--port",   type=int, default=5000)
    parser.add_argument("--cert",   required=True, help="Server certificate (PEM)")
    parser.add_argument("--key",    required=True, help="Server private key (PEM)")
    parser.add_argument("--ca",     required=True, help="CA certificate (PEM)")
    parser.add_argument("--tun-ip", default="10.8.0.1")
    parser.add_argument("--debug",  action="store_true")
    args = parser.parse_args()

    logging.basicConfig(
        level=logging.DEBUG if args.debug else logging.INFO,
        format="%(asctime)s [SERVER] %(levelname)s %(message)s",
    )

    if os.geteuid() != 0:
        sys.exit("Must run as root (sudo)")

    with VPNServer(
        host=args.host, port=args.port,
        cert=args.cert, key=args.key, ca=args.ca,
        tun_ip=args.tun_ip,
    ):
        try:
            while True:
                time.sleep(1)
        except KeyboardInterrupt:
            print("\nShutting down...")


if __name__ == "__main__":
    _main()

#!/usr/bin/env python3
"""
Simple Python VPN - Server
Uses TUN interface + AES-GCM encryption over UDP

Requirements:
    pip install cryptography

Usage (as root):
    python3 vpn_server.py --host 0.0.0.0 --port 5000 --key <32-byte-hex-key>

Generate a key:
    python3 -c "import os; print(os.urandom(32).hex())"
"""

import os
import sys
import struct
import socket
import fcntl
import select
import argparse
import logging
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

logging.basicConfig(level=logging.INFO, format="%(asctime)s [SERVER] %(message)s")
log = logging.getLogger(__name__)

TUNSETIFF = 0x400454CA
IFF_TUN   = 0x0001
IFF_NO_PI = 0x1000
BUFFER_SIZE = 4096


def create_tun(name="tun0"):
    """Create and configure a TUN interface."""
    tun = open("/dev/net/tun", "r+b", buffering=0)
    ifr = struct.pack("16sH", name.encode(), IFF_TUN | IFF_NO_PI)
    fcntl.ioctl(tun, TUNSETIFF, ifr)
    log.info(f"TUN interface '{name}' created")
    return tun


def configure_interface(name, local_ip, peer_ip, mtu=1400):
    """Assign IPs and bring the interface up."""
    os.system(f"ip addr add {local_ip}/24 dev {name}")
    os.system(f"ip link set dev {name} up mtu {mtu}")
    log.info(f"Interface {name}: {local_ip} <-> {peer_ip}")


def encrypt(key: bytes, plaintext: bytes) -> bytes:
    nonce = os.urandom(12)
    ct = AESGCM(key).encrypt(nonce, plaintext, None)
    return nonce + ct


def decrypt(key: bytes, data: bytes) -> bytes:
    nonce, ct = data[:12], data[12:]
    return AESGCM(key).decrypt(nonce, ct, None)


def run_server(host, port, key, tun_ip="10.8.0.1", client_ip="10.8.0.2"):
    tun = create_tun("tun0")
    configure_interface("tun0", tun_ip, client_ip)

    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.bind((host, port))
    log.info(f"Listening on UDP {host}:{port}")

    client_addr = None

    try:
        while True:
            rlist, _, _ = select.select([tun, sock], [], [])

            if tun in rlist:
                # Packet from local network → encrypt → send to client
                packet = tun.read(BUFFER_SIZE)
                if client_addr:
                    sock.sendto(encrypt(key, packet), client_addr)

            if sock in rlist:
                # Packet from client → decrypt → inject into TUN
                data, addr = sock.recvfrom(BUFFER_SIZE)
                if client_addr is None:
                    client_addr = addr
                    log.info(f"Client connected from {addr}")
                try:
                    packet = decrypt(key, data)
                    tun.write(packet)
                except Exception as e:
                    log.warning(f"Decryption failed: {e}")

    except KeyboardInterrupt:
        log.info("Server shutting down.")
    finally:
        tun.close()
        sock.close()


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Simple Python VPN Server")
    parser.add_argument("--host", default="0.0.0.0")
    parser.add_argument("--port", type=int, default=5000)
    parser.add_argument("--key", required=True, help="32-byte hex key")
    parser.add_argument("--tun-ip", default="10.8.0.1")
    parser.add_argument("--client-ip", default="10.8.0.2")
    args = parser.parse_args()

    key = bytes.fromhex(args.key)
    assert len(key) == 32, "Key must be 32 bytes (64 hex chars)"

    if os.geteuid() != 0:
        sys.exit("Must run as root (sudo)")

    run_server(args.host, args.port, key, args.tun_ip, args.client_ip)

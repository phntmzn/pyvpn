#!/usr/bin/env python3
"""
Simple Python VPN - Client
Uses TUN interface + AES-GCM encryption over UDP

Requirements:
    pip install cryptography

Usage (as root):
    python3 vpn_client.py --server <server-ip> --port 5000 --key <32-byte-hex-key>

Use the same key as the server.
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

logging.basicConfig(level=logging.INFO, format="%(asctime)s [CLIENT] %(message)s")
log = logging.getLogger(__name__)

TUNSETIFF = 0x400454CA
IFF_TUN   = 0x0001
IFF_NO_PI = 0x1000
BUFFER_SIZE = 4096


def create_tun(name="tun0"):
    tun = open("/dev/net/tun", "r+b", buffering=0)
    ifr = struct.pack("16sH", name.encode(), IFF_TUN | IFF_NO_PI)
    fcntl.ioctl(tun, TUNSETIFF, ifr)
    log.info(f"TUN interface '{name}' created")
    return tun


def configure_interface(name, local_ip, peer_ip, mtu=1400):
    os.system(f"ip addr add {local_ip}/24 dev {name}")
    os.system(f"ip link set dev {name} up mtu {mtu}")
    log.info(f"Interface {name}: {local_ip} <-> {peer_ip}")


def add_route_via_vpn(server_ip, gateway):
    """Route all traffic through VPN, but keep direct route to VPN server."""
    default_gw = os.popen("ip route | grep default | awk '{print $3}'").read().strip()
    if default_gw:
        os.system(f"ip route add {server_ip}/32 via {default_gw}")
    os.system(f"ip route add 0.0.0.0/1 via {gateway}")
    os.system(f"ip route add 128.0.0.0/1 via {gateway}")
    log.info("Default route redirected through VPN")


def encrypt(key: bytes, plaintext: bytes) -> bytes:
    nonce = os.urandom(12)
    ct = AESGCM(key).encrypt(nonce, plaintext, None)
    return nonce + ct


def decrypt(key: bytes, data: bytes) -> bytes:
    nonce, ct = data[:12], data[12:]
    return AESGCM(key).decrypt(nonce, ct, None)


def run_client(server_host, port, key, local_ip="10.8.0.2", server_tun_ip="10.8.0.1", route_all=False):
    tun = create_tun("tun0")
    configure_interface("tun0", local_ip, server_tun_ip)

    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    server_addr = (server_host, port)
    log.info(f"Connecting to server {server_host}:{port}")

    if route_all:
        add_route_via_vpn(server_host, server_tun_ip)

    # Send a hello so server knows our address
    sock.sendto(encrypt(key, b"\x00"), server_addr)
    log.info("Sent handshake to server")

    try:
        while True:
            rlist, _, _ = select.select([tun, sock], [], [])

            if tun in rlist:
                # Packet from local network → encrypt → send to server
                packet = tun.read(BUFFER_SIZE)
                sock.sendto(encrypt(key, packet), server_addr)

            if sock in rlist:
                # Packet from server → decrypt → inject into TUN
                data, _ = sock.recvfrom(BUFFER_SIZE)
                try:
                    packet = decrypt(key, data)
                    if packet != b"\x00":  # skip handshake echo
                        tun.write(packet)
                except Exception as e:
                    log.warning(f"Decryption failed: {e}")

    except KeyboardInterrupt:
        log.info("Client shutting down.")
    finally:
        tun.close()
        sock.close()


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Simple Python VPN Client")
    parser.add_argument("--server", required=True, help="VPN server IP/hostname")
    parser.add_argument("--port", type=int, default=5000)
    parser.add_argument("--key", required=True, help="32-byte hex key")
    parser.add_argument("--local-ip", default="10.8.0.2")
    parser.add_argument("--server-tun-ip", default="10.8.0.1")
    parser.add_argument("--route-all", action="store_true",
                        help="Route all traffic through VPN")
    args = parser.parse_args()

    key = bytes.fromhex(args.key)
    assert len(key) == 32, "Key must be 32 bytes (64 hex chars)"

    if os.geteuid() != 0:
        sys.exit("Must run as root (sudo)")

    run_client(args.server, args.port, key, args.local_ip, args.server_tun_ip, args.route_all)

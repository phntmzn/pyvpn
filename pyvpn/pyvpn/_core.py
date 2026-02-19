"""
pyvpn._core — internal shared primitives
Shared by both VPNClient and VPNServer. Not part of the public API.
"""

import os
import struct
import socket
import fcntl
import datetime
import json
import logging
from collections import deque

from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PrivateKey, X25519PublicKey
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.x509 import load_pem_x509_certificate

log = logging.getLogger(__name__)

# ── Network / TUN constants ───────────────────────────────────────────────────
TUNSETIFF   = 0x400454CA
IFF_TUN     = 0x0001
IFF_NO_PI   = 0x1000
BUFFER_SIZE = 4096
MTU         = 1380

# ── Packet type tags ──────────────────────────────────────────────────────────
TYPE_DATA               = b'\x01'
TYPE_HANDSHAKE          = b'\x02'
TYPE_KEEPALIVE          = b'\x03'
TYPE_HANDSHAKE_RESPONSE = b'\x04'

# ── Timing defaults ───────────────────────────────────────────────────────────
KEEPALIVE_INTERVAL = 15   # seconds
PEER_TIMEOUT       = 45   # seconds
REPLAY_WINDOW_SIZE = 128
RECONNECT_INITIAL  = 2    # seconds
RECONNECT_MAX      = 60   # seconds


# ── TUN interface ─────────────────────────────────────────────────────────────

def create_tun(name: str = "tun0"):
    """Open /dev/net/tun and register interface name. Returns file object."""
    tun = open("/dev/net/tun", "r+b", buffering=0)
    ifr = struct.pack("16sH", name.encode(), IFF_TUN | IFF_NO_PI)
    fcntl.ioctl(tun, TUNSETIFF, ifr)
    log.debug(f"TUN interface '{name}' created")
    return tun


def configure_interface(name: str, local_ip: str, mtu: int = MTU):
    """Assign IP and bring TUN interface up."""
    os.system(f"ip addr flush dev {name} 2>/dev/null")
    os.system(f"ip addr add {local_ip}/24 dev {name}")
    os.system(f"ip link set dev {name} up mtu {mtu}")
    log.info(f"Interface {name}: {local_ip}/24 mtu={mtu}")


def add_default_routes(server_ip: str, gateway: str):
    """Split-route default traffic through VPN gateway, bypass for VPN server itself."""
    default_gw = os.popen("ip route | grep default | awk '{print $3}'").read().strip()
    if default_gw:
        os.system(f"ip route add {server_ip}/32 via {default_gw} 2>/dev/null")
    os.system(f"ip route add 0.0.0.0/1 via {gateway} 2>/dev/null")
    os.system(f"ip route add 128.0.0.0/1 via {gateway} 2>/dev/null")
    log.info("All traffic routed through VPN")


def remove_default_routes(server_ip: str):
    """Undo split-route entries added by add_default_routes."""
    os.system(f"ip route del {server_ip}/32 2>/dev/null")
    os.system("ip route del 0.0.0.0/1 2>/dev/null")
    os.system("ip route del 128.0.0.0/1 2>/dev/null")
    log.info("VPN routes removed")


# ── Certificate helpers ───────────────────────────────────────────────────────

def load_cert(path: str):
    with open(path, "rb") as f:
        return load_pem_x509_certificate(f.read())


def load_privkey(path: str):
    with open(path, "rb") as f:
        return serialization.load_pem_private_key(f.read(), password=None)


def verify_cert_chain(ca_cert, peer_cert):
    """Verify peer_cert is signed by ca_cert and is currently valid. Raises on failure."""
    now = datetime.datetime.utcnow()
    if peer_cert.not_valid_before > now or peer_cert.not_valid_after < now:
        raise ValueError(f"Certificate '{peer_cert.subject.rfc4514_string()}' is expired or not yet valid")
    ca_cert.public_key().verify(
        peer_cert.signature,
        peer_cert.tbs_certificate_bytes,
        ec.ECDSA(hashes.SHA256()),
    )


# ── Cryptography ──────────────────────────────────────────────────────────────

def derive_session_key(local_private: X25519PrivateKey, peer_public_bytes: bytes) -> bytes:
    """X25519 ECDH + HKDF-SHA256 → 32-byte AES session key."""
    peer_pub = X25519PublicKey.from_public_bytes(peer_public_bytes)
    shared   = local_private.exchange(peer_pub)
    return HKDF(
        algorithm=hashes.SHA256(),
        length=32,
        salt=None,
        info=b"pyvpn-session-key-v1",
    ).derive(shared)


def encrypt_packet(session_key: bytes, seq: int, ptype: bytes, plaintext: bytes) -> bytes:
    """
    Wire format: nonce(12) | AES-GCM( ptype(1) | seq(8) | plaintext )
    """
    nonce = os.urandom(12)
    raw   = ptype + struct.pack(">Q", seq) + plaintext
    ct    = AESGCM(session_key).encrypt(nonce, raw, None)
    return nonce + ct


def decrypt_packet(session_key: bytes, data: bytes):
    """
    Returns (ptype: bytes, seq: int, payload: bytes). Raises on any error.
    """
    if len(data) < 12 + 1 + 8:
        raise ValueError("Packet too short")
    nonce, ct = data[:12], data[12:]
    raw       = AESGCM(session_key).decrypt(nonce, ct, None)
    ptype     = raw[0:1]
    seq       = struct.unpack(">Q", raw[1:9])[0]
    payload   = raw[9:]
    return ptype, seq, payload


# ── Replay window ─────────────────────────────────────────────────────────────

class ReplayWindow:
    """Sliding window replay-attack filter. Thread-safe reads, not thread-safe writes."""

    def __init__(self, size: int = REPLAY_WINDOW_SIZE):
        self.size    = size
        self.top     = -1
        self.seen    = set()
        self.history = deque()

    def check_and_add(self, seq: int) -> bool:
        """Return True if seq is fresh and has been registered. False = replay/duplicate."""
        if seq <= self.top - self.size:
            return False
        if seq in self.seen:
            return False
        self.seen.add(seq)
        self.history.append(seq)
        if seq > self.top:
            self.top = seq
        while self.history and self.history[0] <= self.top - self.size:
            self.seen.discard(self.history.popleft())
        return True


# ── Handshake (shared logic) ──────────────────────────────────────────────────

def build_hello(my_cert, my_key) -> bytes:
    """Build a serialised ClientHello / ServerHello payload (JSON bytes)."""
    ecdh_priv = X25519PrivateKey.generate()
    ecdh_pub  = ecdh_priv.public_key().public_bytes(
        serialization.Encoding.Raw, serialization.PublicFormat.Raw
    )
    sig = my_key.sign(ecdh_pub, ec.ECDSA(hashes.SHA256()))
    payload = json.dumps({
        "ecdh_pub": ecdh_pub.hex(),
        "cert_pem": my_cert.public_bytes(serialization.Encoding.PEM).decode(),
        "sig":      sig.hex(),
    }).encode()
    return ecdh_priv, payload


def verify_hello(data: bytes, ca_cert) -> tuple:
    """
    Parse and verify a hello payload.
    Returns (peer_cert, ecdh_pub_bytes) or raises on failure.
    """
    hello             = json.loads(data.decode())
    ecdh_pub_bytes    = bytes.fromhex(hello["ecdh_pub"])
    peer_cert_pem     = hello["cert_pem"].encode()
    sig               = bytes.fromhex(hello["sig"])

    peer_cert = load_pem_x509_certificate(peer_cert_pem)
    verify_cert_chain(ca_cert, peer_cert)
    peer_cert.public_key().verify(sig, ecdh_pub_bytes, ec.ECDSA(hashes.SHA256()))
    return peer_cert, ecdh_pub_bytes

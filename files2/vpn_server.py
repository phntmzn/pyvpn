#!/usr/bin/env python3
"""
PyVPN Server — Production-grade features
=========================================
New in this version:
  • ECDH (X25519) ephemeral key exchange   → perfect forward secrecy per session
  • Mutual X.509 certificate authentication → client identity verified via CA
  • Replay attack protection               → sequence numbers + sliding window
  • Keepalive / dead-peer detection        → evicts stale clients automatically
  • Multi-session re-handshake support     → clients can reconnect seamlessly

Requirements:
    pip install cryptography

Generate certificates first:
    python3 gen_certs.py --out-dir ./certs --server-ip <your-public-ip>

Usage (as root):
    python3 vpn_server.py \\
        --cert certs/server.crt \\
        --key  certs/server.key \\
        --ca   certs/ca.crt \\
        --host 0.0.0.0 --port 5000
"""

import os, sys, struct, socket, fcntl, select, argparse, logging, time, json, hmac, hashlib
from collections import deque

from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PrivateKey
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.x509 import load_pem_x509_certificate
from cryptography.x509.verification import PolicyBuilder, Store
from cryptography.hazmat.primitives.asymmetric import ec, padding
from cryptography import x509
import datetime

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [SERVER] %(levelname)s %(message)s",
    datefmt="%Y-%m-%d %H:%M:%S",
)
log = logging.getLogger(__name__)

# ── Constants ─────────────────────────────────────────────────────────────────
TUNSETIFF   = 0x400454CA
IFF_TUN     = 0x0001
IFF_NO_PI   = 0x1000
BUFFER_SIZE = 4096
MTU         = 1380

# Packet type tags (1 byte, prepended before encryption)
TYPE_DATA      = b'\x01'
TYPE_HANDSHAKE = b'\x02'
TYPE_KEEPALIVE = b'\x03'
TYPE_HANDSHAKE_RESPONSE = b'\x04'

KEEPALIVE_INTERVAL = 15   # seconds between server → client pings
PEER_TIMEOUT       = 45   # seconds before a client is considered dead
REPLAY_WINDOW      = 128  # how many sequence numbers to track


# ── TUN Interface ─────────────────────────────────────────────────────────────

def create_tun(name="tun0"):
    tun = open("/dev/net/tun", "r+b", buffering=0)
    ifr = struct.pack("16sH", name.encode(), IFF_TUN | IFF_NO_PI)
    fcntl.ioctl(tun, TUNSETIFF, ifr)
    log.info(f"TUN interface '{name}' created")
    return tun


def configure_interface(name, local_ip, mtu=MTU):
    os.system(f"ip addr flush dev {name} 2>/dev/null")
    os.system(f"ip addr add {local_ip}/24 dev {name}")
    os.system(f"ip link set dev {name} up mtu {mtu}")
    log.info(f"Interface {name} up: {local_ip}/24 mtu={mtu}")


# ── Certificate Helpers ───────────────────────────────────────────────────────

def load_cert(path):
    with open(path, "rb") as f:
        return load_pem_x509_certificate(f.read())


def load_privkey(path):
    with open(path, "rb") as f:
        return serialization.load_pem_private_key(f.read(), password=None)


def verify_cert_chain(ca_cert, peer_cert):
    """
    Verify peer_cert was signed by ca_cert and is currently valid.
    Returns True on success, raises on failure.
    """
    now = datetime.datetime.utcnow()
    if peer_cert.not_valid_before > now or peer_cert.not_valid_after < now:
        raise ValueError("Peer certificate is expired or not yet valid")
    # Verify signature using CA public key
    ca_pub = ca_cert.public_key()
    ca_pub.verify(
        peer_cert.signature,
        peer_cert.tbs_certificate_bytes,
        ec.ECDSA(hashes.SHA256()),
    )
    return True


# ── Encryption / Decryption ───────────────────────────────────────────────────

def derive_session_key(local_private: X25519PrivateKey, peer_public_bytes: bytes) -> bytes:
    """ECDH key exchange → HKDF-derived 32-byte AES key."""
    from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PublicKey
    peer_pub = X25519PublicKey.from_public_bytes(peer_public_bytes)
    shared = local_private.exchange(peer_pub)
    derived = HKDF(
        algorithm=hashes.SHA256(),
        length=32,
        salt=None,
        info=b"pyvpn-session-key-v1",
    ).derive(shared)
    return derived


def encrypt_packet(session_key: bytes, seq: int, ptype: bytes, plaintext: bytes) -> bytes:
    """Encrypt: [type(1)] + [seq(8)] + [payload], returning nonce+ciphertext."""
    nonce = os.urandom(12)
    seq_bytes = struct.pack(">Q", seq)
    raw = ptype + seq_bytes + plaintext
    ct = AESGCM(session_key).encrypt(nonce, raw, None)
    return nonce + ct


def decrypt_packet(session_key: bytes, data: bytes):
    """Decrypt and return (ptype, seq, payload) or raise on failure."""
    if len(data) < 12 + 1 + 8:
        raise ValueError("Packet too short")
    nonce, ct = data[:12], data[12:]
    raw = AESGCM(session_key).decrypt(nonce, ct, None)
    ptype  = raw[0:1]
    seq    = struct.unpack(">Q", raw[1:9])[0]
    payload = raw[9:]
    return ptype, seq, payload


# ── Replay Protection ─────────────────────────────────────────────────────────

class ReplayWindow:
    """Sliding window to reject replayed or out-of-order packets."""

    def __init__(self, size=REPLAY_WINDOW):
        self.size    = size
        self.top     = -1
        self.seen    = set()
        self.history = deque()

    def check_and_add(self, seq: int) -> bool:
        """Returns True if seq is fresh (not a replay). Registers it."""
        if seq <= self.top - self.size:
            return False  # too old
        if seq in self.seen:
            return False  # duplicate
        self.seen.add(seq)
        self.history.append(seq)
        if seq > self.top:
            self.top = seq
        # Purge old entries
        while self.history and self.history[0] <= self.top - self.size:
            self.seen.discard(self.history.popleft())
        return True


# ── Client Session ────────────────────────────────────────────────────────────

class ClientSession:
    def __init__(self, addr, session_key):
        self.addr         = addr
        self.session_key  = session_key
        self.send_seq     = 0
        self.replay       = ReplayWindow()
        self.last_seen    = time.monotonic()
        self.established  = time.monotonic()
        log.info(f"Session established with {addr}")

    def touch(self):
        self.last_seen = time.monotonic()

    def is_alive(self):
        return (time.monotonic() - self.last_seen) < PEER_TIMEOUT

    def next_seq(self):
        seq = self.send_seq
        self.send_seq += 1
        return seq


# ── Handshake ─────────────────────────────────────────────────────────────────

def perform_handshake(sock, addr, data, server_cert, server_key, ca_cert):
    """
    Handshake protocol (all messages are plain — authentication via signature):
      Client → Server: ClientHello  JSON { ecdh_pub(hex), cert_pem, sig(hex) }
      Server → Client: ServerHello  JSON { ecdh_pub(hex), cert_pem, sig(hex) }
    sig = ECDSA over SHA256( client_ecdh_pub_bytes )  using the sender's cert private key
    Session key = HKDF( X25519(server_priv, client_pub) )
    """
    try:
        hello = json.loads(data.decode())
        client_ecdh_pub_bytes = bytes.fromhex(hello["ecdh_pub"])
        client_cert_pem       = hello["cert_pem"].encode()
        client_sig            = bytes.fromhex(hello["sig"])

        # 1. Verify client certificate chain
        client_cert = load_pem_x509_certificate(client_cert_pem)
        verify_cert_chain(ca_cert, client_cert)
        log.info(f"Client cert verified: {client_cert.subject.rfc4514_string()}")

        # 2. Verify client's signature over its ECDH public key
        client_pub_key = client_cert.public_key()
        client_pub_key.verify(
            client_sig,
            client_ecdh_pub_bytes,
            ec.ECDSA(hashes.SHA256()),
        )
        log.info(f"Client signature verified from {addr}")

        # 3. Generate server ephemeral ECDH key pair
        server_ecdh_priv = X25519PrivateKey.generate()
        server_ecdh_pub  = server_ecdh_priv.public_key().public_bytes(
            serialization.Encoding.Raw, serialization.PublicFormat.Raw
        )

        # 4. Sign our ECDH public key with our cert private key
        server_sig = server_key.sign(server_ecdh_pub, ec.ECDSA(hashes.SHA256()))

        # 5. Send ServerHello
        server_hello = json.dumps({
            "ecdh_pub": server_ecdh_pub.hex(),
            "cert_pem": server_cert.public_bytes(serialization.Encoding.PEM).decode(),
            "sig":      server_sig.hex(),
        }).encode()
        sock.sendto(TYPE_HANDSHAKE_RESPONSE + server_hello, addr)

        # 6. Derive session key
        session_key = derive_session_key(server_ecdh_priv, client_ecdh_pub_bytes)
        return ClientSession(addr, session_key)

    except Exception as e:
        log.warning(f"Handshake failed from {addr}: {e}")
        return None


# ── Main Server Loop ──────────────────────────────────────────────────────────

def run_server(host, port, server_cert, server_key, ca_cert, tun_ip="10.8.0.1"):
    tun = create_tun("tun0")
    configure_interface("tun0", tun_ip)

    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    sock.bind((host, port))
    sock.setblocking(False)
    log.info(f"Listening on UDP {host}:{port}")

    session: ClientSession = None
    last_keepalive = time.monotonic()

    try:
        while True:
            now = time.monotonic()

            # ── Keepalive / Dead-peer detection ───────────────────────────────
            if session:
                if not session.is_alive():
                    log.warning(f"Client {session.addr} timed out — dropping session")
                    session = None
                elif now - last_keepalive >= KEEPALIVE_INTERVAL:
                    try:
                        pkt = encrypt_packet(session.session_key, session.next_seq(), TYPE_KEEPALIVE, b"")
                        sock.sendto(pkt, session.addr)
                    except Exception:
                        pass
                    last_keepalive = now

            timeout = KEEPALIVE_INTERVAL / 2
            rlist, _, _ = select.select([tun, sock], [], [], timeout)

            # ── TUN → Client ──────────────────────────────────────────────────
            if tun in rlist:
                packet = tun.read(BUFFER_SIZE)
                if session:
                    try:
                        enc = encrypt_packet(session.session_key, session.next_seq(), TYPE_DATA, packet)
                        sock.sendto(enc, session.addr)
                    except Exception as e:
                        log.warning(f"Send error: {e}")

            # ── Client → TUN ──────────────────────────────────────────────────
            if sock in rlist:
                try:
                    data, addr = sock.recvfrom(BUFFER_SIZE + 256)
                except BlockingIOError:
                    continue

                # Unencrypted handshake initiation
                if data[:1] == TYPE_HANDSHAKE:
                    log.info(f"Handshake request from {addr}")
                    new_session = perform_handshake(
                        sock, addr, data[1:], server_cert, server_key, ca_cert
                    )
                    if new_session:
                        session = new_session
                        last_keepalive = time.monotonic()
                    continue

                if session is None or addr != session.addr:
                    log.debug(f"Ignoring data from unknown peer {addr}")
                    continue

                try:
                    ptype, seq, payload = decrypt_packet(session.session_key, data)
                except Exception as e:
                    log.warning(f"Decryption failed from {addr}: {e}")
                    continue

                if not session.replay.check_and_add(seq):
                    log.warning(f"Replayed or duplicate packet (seq={seq}) from {addr} — dropped")
                    continue

                session.touch()

                if ptype == TYPE_DATA:
                    tun.write(payload)
                elif ptype == TYPE_KEEPALIVE:
                    log.debug(f"Keepalive from {addr}")
                    # Echo keepalive back
                    pkt = encrypt_packet(session.session_key, session.next_seq(), TYPE_KEEPALIVE, b"")
                    sock.sendto(pkt, addr)

    except KeyboardInterrupt:
        log.info("Server shutting down.")
    finally:
        tun.close()
        sock.close()


# ── Entry Point ───────────────────────────────────────────────────────────────

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="PyVPN Server")
    parser.add_argument("--host",    default="0.0.0.0",   help="Bind address")
    parser.add_argument("--port",    type=int, default=5000)
    parser.add_argument("--cert",    required=True,        help="Path to server certificate (PEM)")
    parser.add_argument("--key",     required=True,        help="Path to server private key (PEM)")
    parser.add_argument("--ca",      required=True,        help="Path to CA certificate (PEM)")
    parser.add_argument("--tun-ip",  default="10.8.0.1",  help="Server TUN interface IP")
    parser.add_argument("--debug",   action="store_true",  help="Enable debug logging")
    args = parser.parse_args()

    if args.debug:
        logging.getLogger().setLevel(logging.DEBUG)

    if os.geteuid() != 0:
        sys.exit("Must run as root (sudo)")

    server_cert = load_cert(args.cert)
    server_key  = load_privkey(args.key)
    ca_cert     = load_cert(args.ca)

    log.info(f"Server cert: {server_cert.subject.rfc4514_string()}")
    log.info(f"CA cert:     {ca_cert.subject.rfc4514_string()}")

    run_server(args.host, args.port, server_cert, server_key, ca_cert, args.tun_ip)

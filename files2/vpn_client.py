#!/usr/bin/env python3
"""
PyVPN Client — Production-grade features
=========================================
New in this version:
  • ECDH (X25519) ephemeral key exchange   → perfect forward secrecy per session
  • Mutual X.509 certificate authentication → server identity verified via CA
  • Replay attack protection               → sequence numbers + sliding window
  • Keepalive / dead-peer detection        → detects dropped connections fast
  • Auto-reconnect with exponential backoff → survives network interruptions

Requirements:
    pip install cryptography

Generate certificates first:
    python3 gen_certs.py --out-dir ./certs

Usage (as root):
    python3 vpn_client.py \\
        --server 203.0.113.42 \\
        --cert certs/client.crt \\
        --key  certs/client.key \\
        --ca   certs/ca.crt
"""

import os, sys, struct, socket, fcntl, select, argparse, logging, time, json
from collections import deque

from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PrivateKey, X25519PublicKey
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.x509 import load_pem_x509_certificate
from cryptography.hazmat.primitives.asymmetric import ec
import datetime

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [CLIENT] %(levelname)s %(message)s",
    datefmt="%Y-%m-%d %H:%M:%S",
)
log = logging.getLogger(__name__)

# ── Constants ─────────────────────────────────────────────────────────────────
TUNSETIFF   = 0x400454CA
IFF_TUN     = 0x0001
IFF_NO_PI   = 0x1000
BUFFER_SIZE = 4096
MTU         = 1380

TYPE_DATA               = b'\x01'
TYPE_HANDSHAKE          = b'\x02'
TYPE_KEEPALIVE          = b'\x03'
TYPE_HANDSHAKE_RESPONSE = b'\x04'

KEEPALIVE_INTERVAL  = 15    # seconds between client → server pings
PEER_TIMEOUT        = 45    # seconds before server is considered dead
REPLAY_WINDOW       = 128

# Reconnect backoff: starts at 2s, doubles up to 60s
RECONNECT_INITIAL   = 2
RECONNECT_MAX       = 60


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


def add_route_via_vpn(server_ip, gateway):
    default_gw = os.popen("ip route | grep default | awk '{print $3}'").read().strip()
    if default_gw:
        os.system(f"ip route add {server_ip}/32 via {default_gw} 2>/dev/null")
    os.system(f"ip route add 0.0.0.0/1 via {gateway} 2>/dev/null")
    os.system(f"ip route add 128.0.0.0/1 via {gateway} 2>/dev/null")
    log.info("Default route redirected through VPN")


def remove_vpn_routes(server_ip):
    os.system(f"ip route del {server_ip}/32 2>/dev/null")
    os.system("ip route del 0.0.0.0/1 2>/dev/null")
    os.system("ip route del 128.0.0.0/1 2>/dev/null")


# ── Certificate Helpers ───────────────────────────────────────────────────────

def load_cert(path):
    with open(path, "rb") as f:
        return load_pem_x509_certificate(f.read())


def load_privkey(path):
    with open(path, "rb") as f:
        return serialization.load_pem_private_key(f.read(), password=None)


def verify_cert_chain(ca_cert, peer_cert):
    now = datetime.datetime.utcnow()
    if peer_cert.not_valid_before > now or peer_cert.not_valid_after < now:
        raise ValueError("Server certificate is expired or not yet valid")
    ca_pub = ca_cert.public_key()
    ca_pub.verify(
        peer_cert.signature,
        peer_cert.tbs_certificate_bytes,
        ec.ECDSA(hashes.SHA256()),
    )
    return True


# ── Encryption ────────────────────────────────────────────────────────────────

def derive_session_key(local_private: X25519PrivateKey, peer_public_bytes: bytes) -> bytes:
    peer_pub = X25519PublicKey.from_public_bytes(peer_public_bytes)
    shared = local_private.exchange(peer_pub)
    return HKDF(
        algorithm=hashes.SHA256(),
        length=32,
        salt=None,
        info=b"pyvpn-session-key-v1",
    ).derive(shared)


def encrypt_packet(session_key: bytes, seq: int, ptype: bytes, plaintext: bytes) -> bytes:
    nonce = os.urandom(12)
    seq_bytes = struct.pack(">Q", seq)
    raw = ptype + seq_bytes + plaintext
    ct = AESGCM(session_key).encrypt(nonce, raw, None)
    return nonce + ct


def decrypt_packet(session_key: bytes, data: bytes):
    if len(data) < 12 + 1 + 8:
        raise ValueError("Packet too short")
    nonce, ct = data[:12], data[12:]
    raw = AESGCM(session_key).decrypt(nonce, ct, None)
    ptype   = raw[0:1]
    seq     = struct.unpack(">Q", raw[1:9])[0]
    payload = raw[9:]
    return ptype, seq, payload


# ── Replay Protection ─────────────────────────────────────────────────────────

class ReplayWindow:
    def __init__(self, size=REPLAY_WINDOW):
        self.size    = size
        self.top     = -1
        self.seen    = set()
        self.history = deque()

    def check_and_add(self, seq: int) -> bool:
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


# ── Handshake ─────────────────────────────────────────────────────────────────

def perform_handshake(sock, server_addr, client_cert, client_key, ca_cert, timeout=10):
    """
    Send ClientHello, wait for ServerHello, verify server cert, derive session key.
    Returns (session_key, send_seq=0, replay_window) or raises on failure.
    """
    # 1. Generate ephemeral ECDH key pair
    ecdh_priv = X25519PrivateKey.generate()
    ecdh_pub  = ecdh_priv.public_key().public_bytes(
        serialization.Encoding.Raw, serialization.PublicFormat.Raw
    )

    # 2. Sign our ECDH public key with our certificate private key
    sig = client_key.sign(ecdh_pub, ec.ECDSA(hashes.SHA256()))

    # 3. Send ClientHello (plaintext — no session key yet)
    hello = json.dumps({
        "ecdh_pub": ecdh_pub.hex(),
        "cert_pem": client_cert.public_bytes(serialization.Encoding.PEM).decode(),
        "sig":      sig.hex(),
    }).encode()
    sock.sendto(TYPE_HANDSHAKE + hello, server_addr)
    log.info("ClientHello sent, waiting for ServerHello...")

    # 4. Wait for ServerHello
    sock.settimeout(timeout)
    try:
        data, addr = sock.recvfrom(BUFFER_SIZE)
    except socket.timeout:
        raise TimeoutError("Handshake timed out — no response from server")
    finally:
        sock.settimeout(None)

    if data[:1] != TYPE_HANDSHAKE_RESPONSE:
        raise ValueError(f"Expected ServerHello, got type {data[:1].hex()}")

    server_hello = json.loads(data[1:].decode())
    server_ecdh_pub_bytes = bytes.fromhex(server_hello["ecdh_pub"])
    server_cert_pem       = server_hello["cert_pem"].encode()
    server_sig            = bytes.fromhex(server_hello["sig"])

    # 5. Verify server certificate
    server_cert = load_pem_x509_certificate(server_cert_pem)
    verify_cert_chain(ca_cert, server_cert)
    log.info(f"Server cert verified: {server_cert.subject.rfc4514_string()}")

    # 6. Verify server's signature over its ECDH public key
    server_pub_key = server_cert.public_key()
    server_pub_key.verify(
        server_sig,
        server_ecdh_pub_bytes,
        ec.ECDSA(hashes.SHA256()),
    )
    log.info("Server signature verified — handshake complete ✓")

    # 7. Derive session key
    session_key = derive_session_key(ecdh_priv, server_ecdh_pub_bytes)
    return session_key


# ── Main Client Loop ──────────────────────────────────────────────────────────

def run_client(server_host, port, client_cert, client_key, ca_cert,
               local_ip="10.8.0.2", server_tun_ip="10.8.0.1", route_all=False):

    tun = create_tun("tun0")
    configure_interface("tun0", local_ip)

    server_addr  = (server_host, port)
    reconnect_delay = RECONNECT_INITIAL
    routes_added    = False

    try:
        while True:
            # ── Connect / Reconnect ───────────────────────────────────────────
            sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            sock.setblocking(False)

            log.info(f"Connecting to {server_host}:{port}...")
            try:
                session_key  = perform_handshake(sock, server_addr, client_cert, client_key, ca_cert)
                send_seq     = 0
                replay       = ReplayWindow()
                last_seen    = time.monotonic()
                last_ka_sent = time.monotonic()
                reconnect_delay = RECONNECT_INITIAL  # reset backoff on success

                if route_all and not routes_added:
                    add_route_via_vpn(server_host, server_tun_ip)
                    routes_added = True

                log.info("Tunnel established — forwarding packets")

            except Exception as e:
                log.error(f"Connection failed: {e}")
                sock.close()
                log.info(f"Retrying in {reconnect_delay}s...")
                time.sleep(reconnect_delay)
                reconnect_delay = min(reconnect_delay * 2, RECONNECT_MAX)
                continue

            # ── Packet forwarding loop ────────────────────────────────────────
            connected = True
            while connected:
                now = time.monotonic()

                # Dead-peer detection
                if now - last_seen > PEER_TIMEOUT:
                    log.warning("Server heartbeat timeout — reconnecting...")
                    connected = False
                    break

                # Send keepalive
                if now - last_ka_sent >= KEEPALIVE_INTERVAL:
                    try:
                        pkt = encrypt_packet(session_key, send_seq, TYPE_KEEPALIVE, b"")
                        send_seq += 1
                        sock.sendto(pkt, server_addr)
                        last_ka_sent = now
                    except Exception:
                        pass

                timeout = KEEPALIVE_INTERVAL / 2
                rlist, _, _ = select.select([tun, sock], [], [], timeout)

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
                        data, addr = sock.recvfrom(BUFFER_SIZE + 256)
                    except BlockingIOError:
                        continue

                    try:
                        ptype, seq, payload = decrypt_packet(session_key, data)
                    except Exception as e:
                        log.warning(f"Decryption failed: {e}")
                        continue

                    if not replay.check_and_add(seq):
                        log.warning(f"Replayed packet (seq={seq}) — dropped")
                        continue

                    last_seen = time.monotonic()

                    if ptype == TYPE_DATA:
                        tun.write(payload)
                    elif ptype == TYPE_KEEPALIVE:
                        log.debug("Keepalive from server")

            sock.close()
            log.info(f"Reconnecting in {reconnect_delay}s...")
            time.sleep(reconnect_delay)
            reconnect_delay = min(reconnect_delay * 2, RECONNECT_MAX)

    except KeyboardInterrupt:
        log.info("Client shutting down.")
    finally:
        if routes_added:
            remove_vpn_routes(server_host)
        tun.close()


# ── Entry Point ───────────────────────────────────────────────────────────────

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="PyVPN Client")
    parser.add_argument("--server",        required=True,       help="VPN server IP or hostname")
    parser.add_argument("--port",          type=int, default=5000)
    parser.add_argument("--cert",          required=True,       help="Path to client certificate (PEM)")
    parser.add_argument("--key",           required=True,       help="Path to client private key (PEM)")
    parser.add_argument("--ca",            required=True,       help="Path to CA certificate (PEM)")
    parser.add_argument("--local-ip",      default="10.8.0.2",  help="Client TUN interface IP")
    parser.add_argument("--server-tun-ip", default="10.8.0.1",  help="Server TUN IP (gateway)")
    parser.add_argument("--route-all",     action="store_true", help="Route all traffic through VPN")
    parser.add_argument("--debug",         action="store_true", help="Enable debug logging")
    args = parser.parse_args()

    if args.debug:
        logging.getLogger().setLevel(logging.DEBUG)

    if os.geteuid() != 0:
        sys.exit("Must run as root (sudo)")

    client_cert = load_cert(args.cert)
    client_key  = load_privkey(args.key)
    ca_cert     = load_cert(args.ca)

    log.info(f"Client cert: {client_cert.subject.rfc4514_string()}")
    log.info(f"CA cert:     {ca_cert.subject.rfc4514_string()}")

    run_client(
        args.server, args.port,
        client_cert, client_key, ca_cert,
        args.local_ip, args.server_tun_ip, args.route_all,
    )

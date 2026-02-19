# 🔒 PyVPN — Python VPN with Production Security Features

A lightweight VPN tunnel built in Python featuring mutual certificate authentication, ephemeral ECDH key exchange (perfect forward secrecy), replay attack protection, keepalive/dead-peer detection, and automatic reconnection with exponential backoff.

> ⚠️ **Disclaimer:** This is an educational/hobbyist project demonstrating how production VPN security features work. For critical infrastructure, use [WireGuard](https://www.wireguard.com/) or [OpenVPN](https://openvpn.net/).

---

## Table of Contents

- [What's New](#whats-new)
- [How It Works](#how-it-works)
- [Architecture](#architecture)
- [Requirements](#requirements)
- [Installation](#installation)
- [Quick Start](#quick-start)
- [Configuration](#configuration)
- [Routing All Traffic Through the VPN](#routing-all-traffic-through-the-vpn)
- [Security Model](#security-model)
- [Troubleshooting](#troubleshooting)
- [Limitations](#limitations)
- [How VPNs Work (Background)](#how-vpns-work-background)

---

## What's New

This version adds the three major security and reliability features that were missing from the original:

| Feature | How it's implemented |
|---------|---------------------|
| **Certificate-based authentication** | Mutual X.509 cert verification during handshake — both sides verify the other was signed by the trusted CA |
| **Ephemeral key exchange** | X25519 ECDH per session, keys derived via HKDF — provides perfect forward secrecy |
| **Reconnection logic** | Client auto-reconnects with exponential backoff (2s → 4s → ... → 60s cap) |
| **Replay attack protection** | 64-bit sequence numbers + sliding window (128 slots) — replayed or duplicate packets are dropped |
| **Keepalive / dead-peer detection** | Heartbeat every 15s, peer timeout at 45s — broken connections are detected and recovered quickly |

A new helper script `gen_certs.py` generates the CA, server certificate, and client certificate needed for mutual auth.

---

## How It Works

PyVPN creates an encrypted tunnel between two machines in two phases: **handshake** and **data forwarding**.

### Handshake (mutual authentication + key exchange)

```
Client                                          Server
  │                                               │
  ├─── ClientHello ──────────────────────────────►│
  │    { ecdh_pub, cert_pem, sig }                │
  │                                               │  verify client cert (CA chain)
  │                                               │  verify sig(ecdh_pub)
  │                                               │  generate server ECDH key pair
  │◄─── ServerHello ──────────────────────────────┤
  │     { ecdh_pub, cert_pem, sig }               │
  │                                               │
  │  verify server cert (CA chain)                │
  │  verify sig(ecdh_pub)                         │
  │                                               │
  ╠══ both sides: X25519(priv, peer_pub) → HKDF → session_key ══╣
  │                                               │
  │◄══════════ AES-256-GCM encrypted tunnel ══════►│
```

### Data forwarding

```
[Your App]
    ↓ normal IP packet
[tun0 interface]
    ↓ PyVPN reads packet
[seq++ | AES-256-GCM encrypt]
    ↓ encrypted UDP datagram
[Internet / Network]
    ↓ encrypted UDP datagram
[AES-256-GCM decrypt | replay check]
    ↓ original IP packet
[tun0 interface]
    ↓ injected into OS
[Remote App / Internet]
```

---

## Architecture

```
gen_certs.py        — One-time certificate generation (CA + server + client)
vpn_server.py       — Runs on the remote/cloud machine
vpn_client.py       — Runs on your local machine
```

Key components:

| Component | Description |
|-----------|-------------|
| `gen_certs.py` | Generates a CA, server cert, and client cert using ECDSA P-256 |
| `perform_handshake()` | Mutual cert verification + X25519 ECDH + HKDF key derivation |
| `encrypt_packet()` | Prepends type byte + 8-byte seq, then AES-256-GCM with random nonce |
| `decrypt_packet()` | Decrypts and returns `(type, seq, payload)` |
| `ReplayWindow` | Sliding window tracking last 128 sequence numbers |
| `ClientSession` | Tracks session key, sequence counter, replay window, and last-seen time |
| `select()` loop | Multiplexes TUN reads, UDP reads, keepalive timer, and dead-peer detection |

**Virtual IP layout (default):**

```
Server TUN IP:  10.8.0.1
Client TUN IP:  10.8.0.2
Subnet:         10.8.0.0/24
```

---

## Requirements

- **OS:** Linux (requires `/dev/net/tun` — not available on macOS or Windows natively)
- **Python:** 3.7+
- **Privileges:** Must run as `root` (or with `CAP_NET_ADMIN` capability)
- **Dependency:** `cryptography` library

### System packages (if not already installed)

```bash
# Debian/Ubuntu
sudo apt install python3 python3-pip iproute2

# Fedora/RHEL
sudo dnf install python3 python3-pip iproute
```

---

## Installation

**1. Clone or download the scripts**

```bash
git clone https://github.com/yourname/pyvpn.git
cd pyvpn
```

**2. Install the Python dependency**

```bash
pip install cryptography
```

**3. Generate certificates**

Run `gen_certs.py` once to create your CA and signed certificates. Pass your server's public IP so the certificate's Subject Alternative Name is correct.

```bash
python3 gen_certs.py --out-dir ./certs --server-ip 203.0.113.42
```

This creates:

```
certs/
  ca.crt        ← shared trust anchor (copy to both machines)
  ca.key        ← keep offline after signing — not needed at runtime
  server.crt    ← server identity certificate
  server.key    ← server private key
  client.crt    ← client identity certificate
  client.key    ← client private key
```

**4. Distribute files to each machine**

```
Server machine needs:   ca.crt  server.crt  server.key
Client machine needs:   ca.crt  client.crt  client.key
```

Use `scp` or another secure channel — never send private keys unencrypted.

---

## Quick Start

### On the Server (remote machine)

```bash
sudo python3 vpn_server.py \
  --cert certs/server.crt \
  --key  certs/server.key \
  --ca   certs/ca.crt \
  --host 0.0.0.0 \
  --port 5000
```

The server will:
- Create a `tun0` interface with IP `10.8.0.1`
- Listen on UDP port `5000` for incoming connections
- Perform mutual certificate authentication before accepting any traffic
- Derive a fresh session key for each new client connection

### On the Client (your local machine)

```bash
sudo python3 vpn_client.py \
  --server 203.0.113.42 \
  --cert certs/client.crt \
  --key  certs/client.key \
  --ca   certs/ca.crt
```

The client will:
- Create a `tun0` interface with IP `10.8.0.2`
- Perform the ECDH handshake and verify the server's certificate
- Begin forwarding packets, sending keepalives every 15 seconds
- Automatically reconnect if the connection drops

### Verify the tunnel is working

On the client, ping the server through the tunnel:

```bash
ping 10.8.0.1
```

If you get replies, the VPN tunnel is up and working.

---

## Configuration

### Certificate generation options (`gen_certs.py`)

| Flag | Default | Description |
|------|---------|-------------|
| `--out-dir` | `./certs` | Directory to write certificate files |
| `--server-cn` | `pyvpn-server` | Server certificate common name |
| `--client-cn` | `pyvpn-client` | Client certificate common name |
| `--server-ip` | *(none)* | Add an IP SAN to the server cert (repeatable) |
| `--server-dns` | *(none)* | Add a DNS SAN to the server cert (repeatable) |
| `--days-ca` | `3650` | CA validity period in days (default: 10 years) |
| `--days-leaf` | `365` | Server/client cert validity in days (default: 1 year) |

### Server options (`vpn_server.py`)

| Flag | Default | Description |
|------|---------|-------------|
| `--host` | `0.0.0.0` | Interface to listen on |
| `--port` | `5000` | UDP port to listen on |
| `--cert` | *(required)* | Path to server certificate PEM |
| `--key` | *(required)* | Path to server private key PEM |
| `--ca` | *(required)* | Path to CA certificate PEM |
| `--tun-ip` | `10.8.0.1` | Server-side TUN interface IP |
| `--debug` | off | Enable verbose debug logging |

### Client options (`vpn_client.py`)

| Flag | Default | Description |
|------|---------|-------------|
| `--server` | *(required)* | Server's public IP or hostname |
| `--port` | `5000` | UDP port to connect to |
| `--cert` | *(required)* | Path to client certificate PEM |
| `--key` | *(required)* | Path to client private key PEM |
| `--ca` | *(required)* | Path to CA certificate PEM |
| `--local-ip` | `10.8.0.2` | Client-side TUN interface IP |
| `--server-tun-ip` | `10.8.0.1` | Server's TUN IP (used as VPN gateway) |
| `--route-all` | off | Route all internet traffic through VPN |
| `--debug` | off | Enable verbose debug logging |

---

## Routing All Traffic Through the VPN

By default, only traffic destined for `10.8.0.0/24` goes through the tunnel. To route **all** your internet traffic through the VPN server (like a traditional VPN), add `--route-all` to the client:

```bash
sudo python3 vpn_client.py \
  --server 203.0.113.42 \
  --port 5000 \
  --key <your-key> \
  --route-all
```

What `--route-all` does behind the scenes:

```bash
# Keep a direct route to the VPN server itself (so the tunnel doesn't loop)
ip route add <server-ip>/32 via <original-default-gateway>

# Split the default route into two halves (avoids replacing the default route)
ip route add 0.0.0.0/1   via 10.8.0.1
ip route add 128.0.0.0/1 via 10.8.0.1
```

To restore normal routing after stopping the client:

```bash
sudo ip route del 0.0.0.0/1
sudo ip route del 128.0.0.0/1
sudo ip route del <server-ip>/32
```

---

## Security Model

### Authentication — Mutual X.509 Certificates

Both sides present a certificate signed by the shared CA during the handshake. Neither side accepts a connection from a peer whose certificate was not signed by that CA. This means:

- A rogue server cannot impersonate the real server (the client will reject its cert).
- An unauthorized client cannot connect (the server will reject its cert).
- The CA private key (`ca.key`) can be kept offline after signing — it is never needed at runtime.

### Key Exchange — X25519 ECDH + HKDF (Perfect Forward Secrecy)

Each session generates a fresh ephemeral X25519 key pair. The shared secret is derived via X25519 ECDH, then passed through HKDF-SHA256 to produce the 32-byte AES session key. Each side signs its ECDH public key with its certificate private key so the key exchange is authenticated.

Because the ephemeral keys are never stored, recording today's traffic and later stealing the server's certificate private key does not allow decrypting past sessions. This property is called **perfect forward secrecy**.

### Encryption — AES-256-GCM

Each packet is encrypted with AES-256-GCM using a random 12-byte nonce, providing confidentiality, integrity, and authenticity. The packet wire format is:

```
[ 12-byte nonce ][ AES-256-GCM ciphertext ]
    where plaintext = [ type(1) ][ seq(8) ][ payload ]
```

### Replay Attack Protection

Every packet carries a monotonically increasing 64-bit sequence number inside the ciphertext. The receiver maintains a sliding window of the last 128 sequence numbers. Packets with a sequence number already seen, or older than the window, are silently dropped.

### What this implementation still does NOT provide

| Feature | Status | Notes |
|---------|--------|-------|
| Multi-client support | ❌ | One client per server instance |
| Certificate revocation (CRL/OCSP) | ❌ | Revoked certs cannot be blocked without restarting |
| Encrypted handshake | ⚠️ | ClientHello/ServerHello are plaintext (certs visible to observer) |
| DoS resistance | ❌ | No rate limiting or cookie challenge on handshake |

---

## Troubleshooting

**`Operation not permitted` or `Permission denied`**
You must run both scripts with `sudo` or as root. TUN interfaces require kernel-level access.

```bash
sudo python3 vpn_server.py ...
```

**`No such file or directory: '/dev/net/tun'`**
The TUN kernel module isn't loaded. Enable it with:

```bash
sudo modprobe tun
```

To make it persist across reboots:
```bash
echo "tun" | sudo tee /etc/modules-load.d/tun.conf
```

**`Address already in use`**
Another process is using UDP port 5000. Change the port with `--port`, or find and kill the existing process:

```bash
sudo lsof -i udp:5000
```

**Ping to `10.8.0.1` times out**
- Confirm the server is running and reachable: `nc -vzu <server-ip> 5000`
- Check that the server's firewall allows UDP on the chosen port:
  ```bash
  sudo ufw allow 5000/udp
  # or
  sudo iptables -A INPUT -p udp --dport 5000 -j ACCEPT
  ```
- Make sure IP forwarding is enabled on the server if you're routing all traffic:
  ```bash
  echo 1 | sudo tee /proc/sys/net/ipv4/ip_forward
  ```

**Decryption failed warnings**
This means a packet arrived with an invalid authentication tag — it was either corrupted in transit or encrypted with a different key. Double-check that both sides use the exact same `--key` value.

**High latency or poor performance**
Python is not ideal for high-throughput packet processing. For better performance, increase the MTU carefully or switch to a compiled VPN solution.

---

## Limitations

This project demonstrates the core techniques used by production VPNs but remains simplified in a few areas:

- **Single client only.** The server tracks one client session at a time. A second client connecting will replace the first.
- **Plaintext handshake.** The ClientHello and ServerHello are not encrypted, so a passive observer can see the certificates (though not the traffic). WireGuard encrypts its handshake using ephemeral keys to hide identity.
- **No certificate revocation.** There is no CRL or OCSP support. To revoke a client, you'd need to reissue the CA or restart the server with a different CA cert.
- **No DoS protection.** The server processes every handshake request immediately with no rate limiting or cookie challenge. A real VPN would use SYN-cookie-like mechanisms.
- **Linux only.** TUN/TAP interfaces work natively on Linux. macOS requires `utun` via system calls, and Windows requires a TAP driver.

---

## How VPNs Work (Background)

If you're new to VPNs, here's a brief primer on the concepts this project demonstrates.

**TUN vs TAP interfaces**

The Linux kernel supports two types of virtual network interfaces:

- **TUN** (network TUNnel) — operates at Layer 3 (IP packets). This is what PyVPN uses.
- **TAP** (network TAP) — operates at Layer 2 (Ethernet frames). Used when you need to bridge networks at the Ethernet level.

**Why UDP?**

Most VPN protocols (WireGuard, OpenVPN's default mode) use UDP rather than TCP for the outer tunnel. If you use TCP inside TCP, every lost packet causes two layers of retransmission logic to fight each other, causing severe performance degradation — this is known as "TCP meltdown." UDP avoids this by letting the inner TCP handle its own reliability.

**MTU and fragmentation**

The VPN adds overhead to each packet (nonce + auth tag + UDP/IP headers). The TUN interface is configured with a lower MTU (1400 bytes vs the standard 1500) so that after adding VPN overhead, the outer packet still fits within the standard Ethernet MTU and doesn't need to be fragmented.

---

## License

MIT License. Use freely, modify openly, attribute kindly.

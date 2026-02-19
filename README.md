# 🔒 PyVPN — Simple Python VPN

A lightweight, encrypted VPN tunnel built in Python using TUN interfaces and AES-256-GCM authenticated encryption over UDP. Built for learning, experimentation, and understanding how VPNs work under the hood.

> ⚠️ **Disclaimer:** This is an educational project. For production environments, use battle-tested solutions like [WireGuard](https://www.wireguard.com/) or [OpenVPN](https://openvpn.net/). This implementation lacks features like certificate-based authentication, key exchange protocols, and reconnection logic that production VPNs require.

---

## Table of Contents

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

## How It Works

PyVPN creates an encrypted tunnel between two machines using the following approach:

1. A virtual **TUN network interface** (`tun0`) is created on both the server and client.
2. The OS routes IP packets into this interface just like any other network interface.
3. PyVPN reads packets out of the TUN, **encrypts them** using AES-256-GCM, and sends them over a standard UDP socket to the other end.
4. The receiving side **decrypts** the packet and writes it back into its own TUN interface, where the OS picks it up and processes it normally.

From the operating system's perspective, it's just sending packets to a network interface. The encryption and tunneling are entirely transparent.

```
[Your App]
    ↓ normal IP packet
[tun0 interface]
    ↓ PyVPN reads packet
[AES-256-GCM encrypt]
    ↓ encrypted UDP datagram
[Internet / Network]
    ↓ encrypted UDP datagram
[AES-256-GCM decrypt]
    ↓ original IP packet
[tun0 interface]
    ↓ injected into OS
[Remote App / Internet]
```

---

## Architecture

```
vpn_server.py       — Runs on the remote/cloud machine
vpn_client.py       — Runs on your local machine
```

Both scripts share the same core logic:

| Component | Description |
|-----------|-------------|
| `create_tun()` | Opens `/dev/net/tun` and creates a virtual TUN interface |
| `configure_interface()` | Assigns IPs and sets MTU via `ip` commands |
| `encrypt()` | Generates a random 12-byte nonce and encrypts with AES-256-GCM |
| `decrypt()` | Extracts the nonce and decrypts the ciphertext |
| `select()` loop | Watches both the TUN fd and UDP socket simultaneously, forwarding packets in both directions |

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

**3. Generate a shared secret key**

Both the server and client must use the same 32-byte (256-bit) key. Generate one with:

```bash
python3 -c "import os; print(os.urandom(32).hex())"
```

Example output:
```
a3f1c2d4e5b6a7f8091a2b3c4d5e6f7081920a1b2c3d4e5f60718293a4b5c6d
```

Save this key securely — anyone with this key can decrypt your VPN traffic.

---

## Quick Start

### On the Server (remote machine)

```bash
sudo python3 vpn_server.py \
  --host 0.0.0.0 \
  --port 5000 \
  --key a3f1c2d4e5b6a7f8091a2b3c4d5e6f7081920a1b2c3d4e5f60718293a4b5c6d
```

The server will:
- Create a `tun0` interface with IP `10.8.0.1`
- Listen on UDP port `5000` for incoming connections
- Log the client's address when it first connects

### On the Client (your local machine)

```bash
sudo python3 vpn_client.py \
  --server 203.0.113.42 \
  --port 5000 \
  --key a3f1c2d4e5b6a7f8091a2b3c4d5e6f7081920a1b2c3d4e5f60718293a4b5c6d
```

Replace `203.0.113.42` with your server's public IP address.

The client will:
- Create a `tun0` interface with IP `10.8.0.2`
- Send a handshake packet so the server learns the client's address
- Begin forwarding packets in both directions

### Verify the tunnel is working

On the client, ping the server through the tunnel:

```bash
ping 10.8.0.1
```

If you get replies, the VPN tunnel is up and working.

---

## Configuration

### Server options

| Flag | Default | Description |
|------|---------|-------------|
| `--host` | `0.0.0.0` | Interface to listen on |
| `--port` | `5000` | UDP port to listen on |
| `--key` | *(required)* | 32-byte hex-encoded pre-shared key |
| `--tun-ip` | `10.8.0.1` | Server-side TUN interface IP |
| `--client-ip` | `10.8.0.2` | Expected client TUN IP (informational) |

### Client options

| Flag | Default | Description |
|------|---------|-------------|
| `--server` | *(required)* | Server's public IP or hostname |
| `--port` | `5000` | UDP port to connect to |
| `--key` | *(required)* | 32-byte hex-encoded pre-shared key |
| `--local-ip` | `10.8.0.2` | Client-side TUN interface IP |
| `--server-tun-ip` | `10.8.0.1` | Server's TUN IP (used as gateway) |
| `--route-all` | `false` | Route all internet traffic through VPN |

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

### Encryption

PyVPN uses **AES-256-GCM** (Galois/Counter Mode), which provides:

- **Confidentiality** — Traffic cannot be read by a passive observer.
- **Integrity** — Any modification to the ciphertext will cause decryption to fail. Tampered packets are silently dropped.
- **Authenticity** — Only parties with the pre-shared key can produce valid ciphertexts.

Each packet gets a fresh random **12-byte nonce**, prepended to the ciphertext before sending. This means even if the same plaintext is sent twice, the ciphertext will be different each time.

```
Sent packet layout:
[ 12-byte nonce ][ ciphertext + 16-byte GCM auth tag ]
```

### What this implementation does NOT provide

| Feature | Status | Notes |
|---------|--------|-------|
| Key exchange (e.g. Diffie-Hellman) | ❌ | Key must be shared out-of-band |
| Certificate-based identity | ❌ | No way to verify server identity |
| Perfect forward secrecy | ❌ | Same key used for all sessions |
| Replay attack protection | ❌ | No sequence numbers or timestamps |
| Multi-client support | ❌ | One client per server instance |
| Reconnection / keepalive | ❌ | Must restart manually on disconnect |

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

This project is intentionally minimal to keep the code readable and educational. Here's what's missing compared to production VPNs:

- **Single client only.** The server tracks one client address at a time. A second client connecting will silently take over.
- **No key negotiation.** The pre-shared key must be distributed manually and securely (e.g. via SSH).
- **No identity verification.** There's no way to confirm you're talking to the real server and not a man-in-the-middle (since there are no certificates).
- **No replay protection.** A recorded packet could theoretically be replayed. Add sequence numbers and a sliding window to mitigate this.
- **UDP only.** TCP-over-TCP (tunneling TCP inside TCP) performs poorly due to double retransmission. UDP is the right choice here, but adds complexity for unreliable links.
- **Linux only.** TUN/TAP interfaces work natively on Linux. macOS requires `utun` via system calls, and Windows requires a TAP driver (like the one from OpenVPN).

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

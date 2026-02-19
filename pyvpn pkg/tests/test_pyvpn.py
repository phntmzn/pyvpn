"""
tests/test_pyvpn.py
====================
Unit tests that do NOT require root or a TUN interface.
Run with: pytest tests/

Covers:
  - Package imports and version
  - Certificate generation and loading
  - Crypto round-trip (encrypt → decrypt)
  - ReplayWindow correctness
  - VPNClient init with PEM strings (no files, no network)
"""

import os
import pytest

# ── Imports ───────────────────────────────────────────────────────────────────

def test_package_imports():
    from pyvpn import VPNClient, VPNServer, generate_certs, load_cert, load_privkey
    assert VPNClient is not None
    assert VPNServer is not None


def test_version():
    import pyvpn
    assert hasattr(pyvpn, "__version__")
    assert pyvpn.__version__ == "2.0.0"


# ── Certificate generation ────────────────────────────────────────────────────

@pytest.fixture(scope="module")
def certs(tmp_path_factory):
    from pyvpn import generate_certs
    out = str(tmp_path_factory.mktemp("certs"))
    return generate_certs(out_dir=out, server_ips=["127.0.0.1"], days_leaf=1)


def test_generate_certs_returns_all_keys(certs):
    expected = {"ca_crt", "ca_key", "server_crt", "server_key", "client_crt", "client_key"}
    assert expected == set(certs.keys())


def test_generated_cert_pem_format(certs):
    assert certs["ca_crt"].startswith("-----BEGIN CERTIFICATE-----")
    assert certs["server_crt"].startswith("-----BEGIN CERTIFICATE-----")
    assert certs["client_crt"].startswith("-----BEGIN CERTIFICATE-----")


def test_generated_key_pem_format(certs):
    assert "PRIVATE KEY" in certs["ca_key"]
    assert "PRIVATE KEY" in certs["server_key"]
    assert "PRIVATE KEY" in certs["client_key"]


def test_generate_certs_writes_files(certs, tmp_path):
    from pyvpn import generate_certs
    result = generate_certs(out_dir=str(tmp_path), days_leaf=1)
    for fname in ["ca.crt", "ca.key", "server.crt", "server.key", "client.crt", "client.key"]:
        assert os.path.exists(os.path.join(str(tmp_path), fname))


def test_key_files_are_mode_600(tmp_path):
    from pyvpn import generate_certs
    generate_certs(out_dir=str(tmp_path), days_leaf=1)
    for fname in ["ca.key", "server.key", "client.key"]:
        mode = oct(os.stat(os.path.join(str(tmp_path), fname)).st_mode)[-3:]
        assert mode == "600", f"{fname} has mode {mode}, expected 600"


# ── cert chain verification ───────────────────────────────────────────────────

def test_verify_cert_chain_passes(certs):
    from cryptography.x509 import load_pem_x509_certificate
    from pyvpn._core import verify_cert_chain
    ca   = load_pem_x509_certificate(certs["ca_crt"].encode())
    srv  = load_pem_x509_certificate(certs["server_crt"].encode())
    cli  = load_pem_x509_certificate(certs["client_crt"].encode())
    verify_cert_chain(ca, srv)   # should not raise
    verify_cert_chain(ca, cli)   # should not raise


def test_verify_cert_chain_rejects_self_signed(certs):
    from cryptography.x509 import load_pem_x509_certificate
    from pyvpn._core import verify_cert_chain
    ca  = load_pem_x509_certificate(certs["ca_crt"].encode())
    # Verify CA against itself — should fail (CA is its own issuer but wrong key for leaf check)
    # Actually CA self-signs fine; test cross-CA rejection
    from pyvpn import generate_certs
    import tempfile
    certs2 = generate_certs(out_dir=tempfile.mkdtemp(), days_leaf=1)
    ca2  = load_pem_x509_certificate(certs2["ca_crt"].encode())
    srv  = load_pem_x509_certificate(certs["server_crt"].encode())
    with pytest.raises(Exception):
        verify_cert_chain(ca2, srv)  # wrong CA → should raise


# ── Crypto round-trip ─────────────────────────────────────────────────────────

def test_encrypt_decrypt_roundtrip():
    from pyvpn._core import encrypt_packet, decrypt_packet, TYPE_DATA
    key = os.urandom(32)
    payload = b"hello, scraping world!"
    seq = 42

    wire = encrypt_packet(key, seq, TYPE_DATA, payload)
    ptype, dec_seq, dec_payload = decrypt_packet(key, wire)

    assert ptype == TYPE_DATA
    assert dec_seq == seq
    assert dec_payload == payload


def test_decrypt_fails_with_wrong_key():
    from pyvpn._core import encrypt_packet, decrypt_packet, TYPE_DATA
    from cryptography.exceptions import InvalidTag
    key1 = os.urandom(32)
    key2 = os.urandom(32)
    wire = encrypt_packet(key1, 0, TYPE_DATA, b"secret")
    with pytest.raises(Exception):   # InvalidTag or similar
        decrypt_packet(key2, wire)


def test_decrypt_fails_on_tampered_ciphertext():
    from pyvpn._core import encrypt_packet, decrypt_packet, TYPE_DATA
    key = os.urandom(32)
    wire = bytearray(encrypt_packet(key, 0, TYPE_DATA, b"data"))
    wire[-1] ^= 0xFF   # flip last byte
    with pytest.raises(Exception):
        decrypt_packet(key, bytes(wire))


def test_nonce_is_random_each_call():
    from pyvpn._core import encrypt_packet, TYPE_DATA
    key = os.urandom(32)
    a = encrypt_packet(key, 0, TYPE_DATA, b"x")
    b = encrypt_packet(key, 0, TYPE_DATA, b"x")
    assert a[:12] != b[:12], "Nonces must be unique per packet"


# ── ECDH key derivation ───────────────────────────────────────────────────────

def test_ecdh_key_derivation_is_symmetric():
    from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PrivateKey
    from cryptography.hazmat.primitives import serialization
    from pyvpn._core import derive_session_key

    alice_priv = X25519PrivateKey.generate()
    bob_priv   = X25519PrivateKey.generate()

    alice_pub = alice_priv.public_key().public_bytes(
        serialization.Encoding.Raw, serialization.PublicFormat.Raw
    )
    bob_pub = bob_priv.public_key().public_bytes(
        serialization.Encoding.Raw, serialization.PublicFormat.Raw
    )

    key_a = derive_session_key(alice_priv, bob_pub)
    key_b = derive_session_key(bob_priv, alice_pub)

    assert key_a == key_b, "ECDH must produce the same key on both sides"
    assert len(key_a) == 32


# ── ReplayWindow ──────────────────────────────────────────────────────────────

def test_replay_window_accepts_fresh():
    from pyvpn._core import ReplayWindow
    w = ReplayWindow()
    assert w.check_and_add(0) is True
    assert w.check_and_add(1) is True
    assert w.check_and_add(100) is True


def test_replay_window_rejects_duplicate():
    from pyvpn._core import ReplayWindow
    w = ReplayWindow()
    w.check_and_add(5)
    assert w.check_and_add(5) is False


def test_replay_window_rejects_too_old():
    from pyvpn._core import ReplayWindow
    w = ReplayWindow(size=10)
    for i in range(20):
        w.check_and_add(i)
    # seq=0 is now outside the window of 10
    assert w.check_and_add(0) is False


def test_replay_window_accepts_in_window():
    from pyvpn._core import ReplayWindow
    w = ReplayWindow(size=10)
    w.check_and_add(15)
    # seq=10 is still within window (15 - 10 = 5 < 10)
    assert w.check_and_add(10) is True


# ── VPNClient init (no root, no network) ─────────────────────────────────────

def test_vpnclient_init_with_pem_strings(certs):
    from pyvpn import VPNClient
    # Should construct without error — no connect() called, so no root needed
    vpn = VPNClient(
        server="127.0.0.1",
        cert_pem=certs["client_crt"],
        key_pem=certs["client_key"],
        ca_pem=certs["ca_crt"],
    )
    assert vpn.server == "127.0.0.1"
    assert vpn.port == 5000
    assert vpn.is_connected is False


def test_vpnclient_init_with_files(certs, tmp_path):
    from pyvpn import VPNClient, generate_certs
    generate_certs(out_dir=str(tmp_path), days_leaf=1)
    vpn = VPNClient(
        server="127.0.0.1",
        cert=str(tmp_path / "client.crt"),
        key=str(tmp_path / "client.key"),
        ca=str(tmp_path / "ca.crt"),
    )
    assert not vpn.is_connected


def test_vpnclient_connect_requires_root(certs):
    """connect() should raise PermissionError when not running as root."""
    from pyvpn import VPNClient
    if os.geteuid() == 0:
        pytest.skip("Running as root — cannot test permission check")
    vpn = VPNClient(
        server="127.0.0.1",
        cert_pem=certs["client_crt"],
        key_pem=certs["client_key"],
        ca_pem=certs["ca_crt"],
    )
    with pytest.raises(PermissionError):
        vpn.connect()


# ── requests_session helper ───────────────────────────────────────────────────

def test_requests_session_returns_session(certs):
    pytest.importorskip("requests")
    import requests
    from pyvpn import VPNClient
    vpn = VPNClient(
        server="127.0.0.1",
        cert_pem=certs["client_crt"],
        key_pem=certs["client_key"],
        ca_pem=certs["ca_crt"],
    )
    # requests_session() doesn't need an active tunnel
    session = vpn.requests_session(headers={"X-Test": "yes"})
    assert isinstance(session, requests.Session)
    assert session.headers["X-Test"] == "yes"


def test_httpx_client_returns_client(certs):
    pytest.importorskip("httpx")
    import httpx
    from pyvpn import VPNClient
    vpn = VPNClient(
        server="127.0.0.1",
        cert_pem=certs["client_crt"],
        key_pem=certs["client_key"],
        ca_pem=certs["ca_crt"],
    )
    client = vpn.httpx_client()
    assert isinstance(client, httpx.Client)
    client.close()

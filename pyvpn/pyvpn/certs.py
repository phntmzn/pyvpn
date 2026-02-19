"""
pyvpn.certs — certificate generation and loading
=================================================
Importable helpers for generating and loading X.509 certificates.

Usage (Python):

    from pyvpn.certs import generate_certs

    certs = generate_certs(out_dir="./certs", server_ips=["203.0.113.42"])
    # certs is a dict: { "ca_crt", "ca_key", "server_crt", "server_key",
    #                    "client_crt", "client_key" }
    # Each value is a PEM string — files are also written to out_dir.

Usage (CLI):

    python3 -m pyvpn.certs --out-dir ./certs --server-ip 203.0.113.42
"""

import os
import sys
import datetime
import argparse
import ipaddress
from typing import List, Optional

from cryptography import x509
from cryptography.x509.oid import NameOID, ExtendedKeyUsageOID
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.x509 import load_pem_x509_certificate


# ── Low-level builders ────────────────────────────────────────────────────────

def _make_key():
    return ec.generate_private_key(ec.SECP256R1())


def _key_pem(key, password=None) -> str:
    enc = (
        serialization.BestAvailableEncryption(password.encode())
        if password else serialization.NoEncryption()
    )
    return key.private_bytes(
        serialization.Encoding.PEM,
        serialization.PrivateFormat.TraditionalOpenSSL,
        enc,
    ).decode()


def _cert_pem(cert) -> str:
    return cert.public_bytes(serialization.Encoding.PEM).decode()


def _make_ca(key, days=3650):
    name = x509.Name([
        x509.NameAttribute(NameOID.COMMON_NAME, "PyVPN CA"),
        x509.NameAttribute(NameOID.ORGANIZATION_NAME, "PyVPN"),
    ])
    now = datetime.datetime.utcnow()
    return (
        x509.CertificateBuilder()
        .subject_name(name).issuer_name(name)
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now)
        .not_valid_after(now + datetime.timedelta(days=days))
        .add_extension(x509.BasicConstraints(ca=True, path_length=None), critical=True)
        .add_extension(x509.SubjectKeyIdentifier.from_public_key(key.public_key()), critical=False)
        .add_extension(x509.KeyUsage(
            digital_signature=True, key_cert_sign=True, crl_sign=True,
            content_commitment=False, key_encipherment=False,
            data_encipherment=False, key_agreement=False,
            encipher_only=False, decipher_only=False,
        ), critical=True)
        .sign(key, hashes.SHA256())
    )


def _make_leaf(cn, ca_cert, ca_key, key, days=365, is_server=False,
               san_ips=None, san_dns=None):
    subject = x509.Name([
        x509.NameAttribute(NameOID.COMMON_NAME, cn),
        x509.NameAttribute(NameOID.ORGANIZATION_NAME, "PyVPN"),
    ])
    now = datetime.datetime.utcnow()
    san_list = []
    for ip in (san_ips or []):
        san_list.append(x509.IPAddress(ipaddress.ip_address(ip)))
    for dns in (san_dns or []):
        san_list.append(x509.DNSName(dns))

    builder = (
        x509.CertificateBuilder()
        .subject_name(subject).issuer_name(ca_cert.subject)
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now)
        .not_valid_after(now + datetime.timedelta(days=days))
        .add_extension(x509.BasicConstraints(ca=False, path_length=None), critical=True)
        .add_extension(x509.AuthorityKeyIdentifier.from_issuer_public_key(ca_key.public_key()), critical=False)
        .add_extension(x509.KeyUsage(
            digital_signature=True, key_cert_sign=False, crl_sign=False,
            content_commitment=False, key_encipherment=False,
            data_encipherment=False, key_agreement=True,
            encipher_only=False, decipher_only=False,
        ), critical=True)
        .add_extension(x509.ExtendedKeyUsage([
            ExtendedKeyUsageOID.SERVER_AUTH if is_server else ExtendedKeyUsageOID.CLIENT_AUTH,
        ]), critical=False)
    )
    if san_list:
        builder = builder.add_extension(x509.SubjectAlternativeName(san_list), critical=False)
    return builder.sign(ca_key, hashes.SHA256())


# ── Public API ────────────────────────────────────────────────────────────────

def generate_certs(
    out_dir: str = "./certs",
    server_cn: str = "pyvpn-server",
    client_cn: str = "pyvpn-client",
    server_ips: Optional[List[str]] = None,
    server_dns: Optional[List[str]] = None,
    days_ca: int = 3650,
    days_leaf: int = 365,
) -> dict:
    """
    Generate a CA, server certificate, and client certificate.

    Writes PEM files to out_dir and also returns them as a dict of strings
    so callers can pass them directly to VPNClient / VPNServer without touching
    the filesystem.

    Parameters
    ----------
    out_dir : str
        Directory to write PEM files into (created if missing).
    server_cn : str
        Common name for the server certificate.
    client_cn : str
        Common name for the client certificate.
    server_ips : list of str
        IP Subject Alternative Names to add to the server cert.
    server_dns : list of str
        DNS Subject Alternative Names to add to the server cert.
    days_ca : int
        CA certificate validity in days (default: 10 years).
    days_leaf : int
        Server/client certificate validity in days (default: 1 year).

    Returns
    -------
    dict with keys:
        ca_crt, ca_key, server_crt, server_key, client_crt, client_key
    Each value is a PEM-encoded string.
    """
    os.makedirs(out_dir, exist_ok=True)

    ca_key  = _make_key()
    ca_cert = _make_ca(ca_key, days=days_ca)

    srv_key  = _make_key()
    srv_cert = _make_leaf(
        server_cn, ca_cert, ca_key, srv_key,
        days=days_leaf, is_server=True,
        san_ips=server_ips, san_dns=server_dns,
    )

    cli_key  = _make_key()
    cli_cert = _make_leaf(
        client_cn, ca_cert, ca_key, cli_key,
        days=days_leaf, is_server=False,
    )

    result = {
        "ca_crt":     _cert_pem(ca_cert),
        "ca_key":     _key_pem(ca_key),
        "server_crt": _cert_pem(srv_cert),
        "server_key": _key_pem(srv_key),
        "client_crt": _cert_pem(cli_cert),
        "client_key": _key_pem(cli_key),
    }

    # Write files
    pairs = [
        ("ca.crt",     result["ca_crt"]),
        ("ca.key",     result["ca_key"]),
        ("server.crt", result["server_crt"]),
        ("server.key", result["server_key"]),
        ("client.crt", result["client_crt"]),
        ("client.key", result["client_key"]),
    ]
    for filename, pem in pairs:
        path = os.path.join(out_dir, filename)
        with open(path, "w") as f:
            f.write(pem)
        if filename.endswith(".key"):
            os.chmod(path, 0o600)

    return result


def load_cert(path: str):
    """Load and return an X.509 certificate from a PEM file."""
    with open(path, "rb") as f:
        return load_pem_x509_certificate(f.read())


def load_privkey(path: str):
    """Load and return a private key from a PEM file."""
    with open(path, "rb") as f:
        return serialization.load_pem_private_key(f.read(), password=None)


# ── CLI ───────────────────────────────────────────────────────────────────────

def _main():
    parser = argparse.ArgumentParser(description="PyVPN Certificate Generator")
    parser.add_argument("--out-dir",    default="./certs")
    parser.add_argument("--server-cn",  default="pyvpn-server")
    parser.add_argument("--client-cn",  default="pyvpn-client")
    parser.add_argument("--server-ip",  action="append", default=[], dest="server_ips")
    parser.add_argument("--server-dns", action="append", default=[], dest="server_dns")
    parser.add_argument("--days-ca",    type=int, default=3650)
    parser.add_argument("--days-leaf",  type=int, default=365)
    args = parser.parse_args()

    print("Generating certificates...")
    generate_certs(
        out_dir=args.out_dir,
        server_cn=args.server_cn,
        client_cn=args.client_cn,
        server_ips=args.server_ips,
        server_dns=args.server_dns,
        days_ca=args.days_ca,
        days_leaf=args.days_leaf,
    )
    print(f"\nDone! Certificates written to: {args.out_dir}/")
    print(f"""
  Server needs: ca.crt  server.crt  server.key
  Client needs: ca.crt  client.crt  client.key
  ca.key:       keep offline — not needed at runtime
""")


if __name__ == "__main__":
    _main()

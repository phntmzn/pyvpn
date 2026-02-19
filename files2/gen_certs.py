#!/usr/bin/env python3
"""
PyVPN Certificate Generator
Generates a CA, server certificate, and client certificate for mutual TLS auth.

Requirements:
    pip install cryptography

Usage:
    python3 gen_certs.py --out-dir ./certs

This creates:
    certs/ca.crt          — Certificate Authority (shared trust anchor)
    certs/ca.key          — CA private key (keep secret, used only to sign)
    certs/server.crt      — Server certificate (signed by CA)
    certs/server.key      — Server private key
    certs/client.crt      — Client certificate (signed by CA)
    certs/client.key      — Client private key
"""

import os
import sys
import argparse
import datetime
from cryptography import x509
from cryptography.x509.oid import NameOID, ExtendedKeyUsageOID
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec


def make_key():
    return ec.generate_private_key(ec.SECP256R1())


def save_key(key, path, password=None):
    enc = (
        serialization.BestAvailableEncryption(password.encode())
        if password
        else serialization.NoEncryption()
    )
    with open(path, "wb") as f:
        f.write(key.private_bytes(
            serialization.Encoding.PEM,
            serialization.PrivateFormat.TraditionalOpenSSL,
            enc,
        ))
    os.chmod(path, 0o600)
    print(f"  Wrote {path}")


def save_cert(cert, path):
    with open(path, "wb") as f:
        f.write(cert.public_bytes(serialization.Encoding.PEM))
    print(f"  Wrote {path}")


def make_ca(key, days=3650):
    name = x509.Name([
        x509.NameAttribute(NameOID.COMMON_NAME, "PyVPN CA"),
        x509.NameAttribute(NameOID.ORGANIZATION_NAME, "PyVPN"),
    ])
    now = datetime.datetime.utcnow()
    cert = (
        x509.CertificateBuilder()
        .subject_name(name)
        .issuer_name(name)
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now)
        .not_valid_after(now + datetime.timedelta(days=days))
        .add_extension(x509.BasicConstraints(ca=True, path_length=None), critical=True)
        .add_extension(x509.SubjectKeyIdentifier.from_public_key(key.public_key()), critical=False)
        .add_extension(
            x509.KeyUsage(
                digital_signature=True, key_cert_sign=True, crl_sign=True,
                content_commitment=False, key_encipherment=False,
                data_encipherment=False, key_agreement=False,
                encipher_only=False, decipher_only=False,
            ),
            critical=True,
        )
        .sign(key, hashes.SHA256())
    )
    return cert


def make_cert(cn, ca_cert, ca_key, key, days=365, is_server=False, san_ips=None, san_dns=None):
    subject = x509.Name([
        x509.NameAttribute(NameOID.COMMON_NAME, cn),
        x509.NameAttribute(NameOID.ORGANIZATION_NAME, "PyVPN"),
    ])
    now = datetime.datetime.utcnow()

    san_list = []
    for ip in (san_ips or []):
        import ipaddress
        san_list.append(x509.IPAddress(ipaddress.ip_address(ip)))
    for dns in (san_dns or []):
        san_list.append(x509.DNSName(dns))

    builder = (
        x509.CertificateBuilder()
        .subject_name(subject)
        .issuer_name(ca_cert.subject)
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now)
        .not_valid_after(now + datetime.timedelta(days=days))
        .add_extension(x509.BasicConstraints(ca=False, path_length=None), critical=True)
        .add_extension(
            x509.AuthorityKeyIdentifier.from_issuer_public_key(ca_key.public_key()),
            critical=False,
        )
        .add_extension(
            x509.KeyUsage(
                digital_signature=True, key_cert_sign=False, crl_sign=False,
                content_commitment=False, key_encipherment=False,
                data_encipherment=False, key_agreement=True,
                encipher_only=False, decipher_only=False,
            ),
            critical=True,
        )
        .add_extension(
            x509.ExtendedKeyUsage([
                ExtendedKeyUsageOID.SERVER_AUTH if is_server else ExtendedKeyUsageOID.CLIENT_AUTH,
            ]),
            critical=False,
        )
    )

    if san_list:
        builder = builder.add_extension(x509.SubjectAlternativeName(san_list), critical=False)

    return builder.sign(ca_key, hashes.SHA256())


def main():
    parser = argparse.ArgumentParser(description="Generate PyVPN certificates")
    parser.add_argument("--out-dir", default="./certs", help="Output directory")
    parser.add_argument("--server-cn", default="pyvpn-server", help="Server common name")
    parser.add_argument("--client-cn", default="pyvpn-client", help="Client common name")
    parser.add_argument("--server-ip", action="append", default=[], help="Server IP SAN (repeatable)")
    parser.add_argument("--server-dns", action="append", default=[], help="Server DNS SAN (repeatable)")
    parser.add_argument("--days-ca", type=int, default=3650, help="CA validity in days (default: 10yr)")
    parser.add_argument("--days-leaf", type=int, default=365, help="Leaf cert validity in days (default: 1yr)")
    args = parser.parse_args()

    os.makedirs(args.out_dir, exist_ok=True)
    print(f"\n[1/4] Generating CA...")
    ca_key = make_key()
    ca_cert = make_ca(ca_key, days=args.days_ca)
    save_key(ca_key, os.path.join(args.out_dir, "ca.key"))
    save_cert(ca_cert, os.path.join(args.out_dir, "ca.crt"))

    print(f"\n[2/4] Generating server certificate ({args.server_cn})...")
    srv_key = make_key()
    srv_cert = make_cert(
        args.server_cn, ca_cert, ca_key, srv_key,
        days=args.days_leaf, is_server=True,
        san_ips=args.server_ip, san_dns=args.server_dns,
    )
    save_key(srv_key, os.path.join(args.out_dir, "server.key"))
    save_cert(srv_cert, os.path.join(args.out_dir, "server.crt"))

    print(f"\n[3/4] Generating client certificate ({args.client_cn})...")
    cli_key = make_key()
    cli_cert = make_cert(
        args.client_cn, ca_cert, ca_key, cli_key,
        days=args.days_leaf, is_server=False,
    )
    save_key(cli_key, os.path.join(args.out_dir, "client.key"))
    save_cert(cli_cert, os.path.join(args.out_dir, "client.crt"))

    print(f"\n[4/4] Done! Files written to '{args.out_dir}/'")
    print("""
Next steps:
  Server: python3 vpn_server.py --cert certs/server.crt --key certs/server.key --ca certs/ca.crt ...
  Client: python3 vpn_client.py --cert certs/client.crt --key certs/client.key --ca certs/ca.crt ...

Distribute to machines:
  → Server needs: ca.crt, server.crt, server.key
  → Client needs: ca.crt, client.crt, client.key
  → ca.key should be kept offline after signing
""")


if __name__ == "__main__":
    main()

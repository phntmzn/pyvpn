"""
pyvpn.client_cli — standalone command-line client
Run: python3 -m pyvpn.client_cli  OR  pyvpn-client (after pip install)
"""

import os
import sys
import time
import logging
import argparse

from .client import VPNClient


def _main():
    parser = argparse.ArgumentParser(description="PyVPN Client")
    parser.add_argument("--server",        required=True)
    parser.add_argument("--port",          type=int, default=5000)
    parser.add_argument("--cert",          required=True, help="Client certificate (PEM)")
    parser.add_argument("--key",           required=True, help="Client private key (PEM)")
    parser.add_argument("--ca",            required=True, help="CA certificate (PEM)")
    parser.add_argument("--local-ip",      default="10.8.0.2")
    parser.add_argument("--server-tun-ip", default="10.8.0.1")
    parser.add_argument("--route-all",     action="store_true", default=True)
    parser.add_argument("--no-route-all",  action="store_false", dest="route_all")
    parser.add_argument("--debug",         action="store_true")
    args = parser.parse_args()

    logging.basicConfig(
        level=logging.DEBUG if args.debug else logging.INFO,
        format="%(asctime)s [CLIENT] %(levelname)s %(message)s",
    )

    if os.geteuid() != 0:
        sys.exit("Must run as root (sudo)")

    vpn = VPNClient(
        server=args.server,
        port=args.port,
        cert=args.cert,
        key=args.key,
        ca=args.ca,
        local_ip=args.local_ip,
        server_tun_ip=args.server_tun_ip,
        route_all=args.route_all,
    )

    with vpn:
        print(f"VPN tunnel established. Press Ctrl+C to disconnect.")
        try:
            while True:
                time.sleep(1)
        except KeyboardInterrupt:
            print("\nDisconnecting...")


if __name__ == "__main__":
    _main()

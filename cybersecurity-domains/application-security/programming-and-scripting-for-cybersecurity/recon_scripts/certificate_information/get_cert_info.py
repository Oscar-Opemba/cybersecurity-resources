#!/usr/bin/env python3
"""get_cert_info — fetch a host's TLS certificate details.

Hardened from the original teaching demo: structured output (text/JSON), a
return value instead of only printing, injectable fetch for testing, and clean
error handling with a non-zero exit on failure.

Performs a read-only TLS handshake against the given host. Authorized use
only. See LEGAL.md at the repository root.
"""

from __future__ import annotations

import argparse
import json
import logging
import sys

log = logging.getLogger("get_cert_info")


class CertError(Exception):
    """Raised when the certificate cannot be retrieved."""


def _default_fetch(hostname: str, port: int, timeout: float = 3.0) -> dict:
    import socket
    import ssl

    context = ssl.create_default_context()
    with socket.create_connection((hostname, port), timeout=timeout) as sock:
        with context.wrap_socket(sock, server_hostname=hostname) as conn:
            return conn.getpeercert()


def get_certificate_info(hostname: str, port: int = 443, fetch=None) -> dict:
    """Return the peer certificate as a dict. ``fetch`` is injectable."""
    fetch = fetch or _default_fetch
    try:
        return fetch(hostname, port)
    except Exception as exc:  # noqa: BLE001 - surface as a clean CertError
        raise CertError(f"could not retrieve certificate: {exc}") from exc


def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        prog="get_cert_info",
        description="Fetch a host's TLS certificate information.",
        epilog="Authorized use only. See LEGAL.md.",
    )
    p.add_argument("domain", nargs="?", help="Domain name, e.g. example.com")
    p.add_argument("--port", type=int, default=443, help="Port (default 443).")
    p.add_argument("--format", choices=["text", "json"], default="text",
                   help="Report format. Default: text")
    return p


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    logging.basicConfig(level=logging.INFO,
                        format="%(asctime)s %(levelname)s %(message)s")

    if not args.domain:
        log.error("No domain given. Example: get_cert_info.py example.com")
        return 2

    try:
        cert = get_certificate_info(args.domain, args.port)
    except CertError as exc:
        log.error("%s", exc)
        return 4

    if args.format == "json":
        print(json.dumps(cert, indent=2, default=str))
    else:
        from pprint import pformat
        print(pformat(cert))
    return 0


if __name__ == "__main__":
    sys.exit(main())

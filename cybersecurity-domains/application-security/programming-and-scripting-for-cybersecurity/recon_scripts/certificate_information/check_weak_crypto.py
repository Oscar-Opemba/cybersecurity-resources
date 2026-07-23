#!/usr/bin/env python3
"""check_weak_crypto — detect deprecated TLS/SSL protocol versions on a host.

WHY THIS WAS REWRITTEN: the original tried ``context.set_ciphers('TLSv1')``,
``set_ciphers('SSLv2')``, etc. Those are not valid OpenSSL cipher strings, so
every attempt raised and was swallowed by ``except: pass`` — the tool never
actually reported anything (and it referenced ``ssl.PROTOCOL_SSL23``, which
does not exist, and closed a possibly-undefined socket in ``finally``). Rather
than ship non-functional detection, this version does a *real* check: it
negotiates each deprecated protocol version and reports which ones the server
accepts.

This is a basic check, NOT a replacement for a dedicated tool (sslyze,
testssl.sh). It performs read-only TLS handshakes. Authorized use only.
See LEGAL.md at the repository root.
"""

from __future__ import annotations

import argparse
import json
import logging
import sys

log = logging.getLogger("check_weak_crypto")

# Deprecated protocol versions considered weak, newest-weak first.
WEAK_PROTOCOLS = ["TLSv1.1", "TLSv1", "SSLv3"]


def _tls_version(name: str):
    import ssl

    return {
        "SSLv3": ssl.TLSVersion.SSLv3,
        "TLSv1": ssl.TLSVersion.TLSv1,
        "TLSv1.1": ssl.TLSVersion.TLSv1_1,
    }[name]


def _default_prober(hostname: str, port: int, proto_name: str,
                    timeout: float = 3.0) -> bool:
    """Return True if the server completes a handshake at ``proto_name``.

    Raises on inability to even test the protocol (e.g. the local OpenSSL
    refuses to enable it), so the caller can distinguish 'rejected' from
    'could not test'.
    """
    import socket
    import ssl

    version = _tls_version(proto_name)
    context = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    context.check_hostname = False
    context.verify_mode = ssl.CERT_NONE
    # Pin the handshake to exactly this (weak) protocol version.
    context.minimum_version = version
    context.maximum_version = version

    with socket.create_connection((hostname, port), timeout=timeout) as sock:
        try:
            with context.wrap_socket(sock, server_hostname=hostname):
                return True  # handshake at a weak version succeeded
        except ssl.SSLError:
            return False  # server refused this weak version — good


def check_weak_crypto(hostname: str, port: int = 443, prober=None) -> dict:
    """Probe each weak protocol. Returns a structured result.

    ``prober(hostname, port, proto_name) -> bool`` is injectable for testing.
    """
    prober = prober or _default_prober
    accepted: list[str] = []
    untested: list[str] = []
    for proto in WEAK_PROTOCOLS:
        try:
            if prober(hostname, port, proto):
                accepted.append(proto)
        except Exception as exc:  # noqa: BLE001 - can't enable/reach this proto
            untested.append(f"{proto}: {exc}")
    return {
        "host": hostname,
        "port": port,
        "weak_protocols_accepted": accepted,
        "untested": untested,
    }


def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        prog="check_weak_crypto",
        description="Detect deprecated TLS/SSL protocol versions on a host.",
        epilog="Authorized use only. See LEGAL.md.",
    )
    p.add_argument("domain", nargs="?", help="Domain to check.")
    p.add_argument("--port", type=int, default=443, help="Port (default 443).")
    p.add_argument("--format", choices=["text", "json"], default="text",
                   help="Report format. Default: text")
    return p


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    logging.basicConfig(level=logging.INFO,
                        format="%(asctime)s %(levelname)s %(message)s")

    if not args.domain:
        log.error("No domain given. Example: check_weak_crypto.py example.com")
        return 2

    result = check_weak_crypto(args.domain, args.port)

    if args.format == "json":
        print(json.dumps(result, indent=2))
        return 0

    if result["weak_protocols_accepted"]:
        print(f"[!] {args.domain}:{args.port} accepts weak protocol(s): "
              f"{', '.join(result['weak_protocols_accepted'])}")
    else:
        print(f"[+] {args.domain}:{args.port} rejected all tested weak "
              "protocols (SSLv3/TLSv1/TLSv1.1).")
    for note in result["untested"]:
        print(f"    (could not test {note})")
    return 0


if __name__ == "__main__":
    sys.exit(main())

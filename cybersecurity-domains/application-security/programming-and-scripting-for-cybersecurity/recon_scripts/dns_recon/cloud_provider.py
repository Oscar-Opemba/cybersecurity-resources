#!/usr/bin/env python3
"""cloud_provider — resolve a domain and guess whether its IP is a major cloud.

Hardened from the original teaching demo: a CLI argument instead of input(),
injectable resolver + WHOIS lookups (so the logic is unit-testable without
network), structured output, and correct error handling. The original caught
``whois.WhoisException`` which python-whois does not define — a bare failure
there would itself have raised.

See LEGAL.md at the repository root.
"""

from __future__ import annotations

import argparse
import json
import logging
import sys

log = logging.getLogger("cloud_provider")

CLOUD_PROVIDERS = [
    "Amazon", "AWS", "Azure", "Microsoft", "Google", "Digital Ocean",
    "DigitalOcean", "Alibaba", "Oracle", "Cloudflare",
]


def _default_resolver(domain: str) -> str | None:
    import socket

    try:
        return socket.gethostbyname(domain)
    except socket.gaierror:
        return None


def _default_whois_org(ip_address: str) -> str | None:
    try:
        import whois
    except ImportError:  # pragma: no cover - optional dep
        return None
    try:
        info = whois.whois(ip_address)
    except Exception:  # noqa: BLE001 - python-whois raises many ad-hoc types
        return None
    org = getattr(info, "org", None)
    return str(org) if org else None


def is_major_cloud_provider(org: str) -> bool:
    org_l = (org or "").lower()
    return any(p.lower() in org_l for p in CLOUD_PROVIDERS)


def analyze(domain: str, *, resolver=None, whois_org=None) -> dict:
    """Return a structured result for ``domain``. Lookups are injectable."""
    resolver = resolver or _default_resolver
    whois_org = whois_org or _default_whois_org

    result = {"domain": domain, "ip": None, "org": None, "cloud_provider": None}
    ip = resolver(domain)
    if not ip:
        return result
    result["ip"] = ip
    org = whois_org(ip)
    if org:
        result["org"] = org
        result["cloud_provider"] = is_major_cloud_provider(org)
    return result


def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        prog="cloud_provider",
        description="Resolve a domain and check if its IP is a major cloud.",
        epilog="Authorized use only. See LEGAL.md.",
    )
    p.add_argument("domain", nargs="?", help="Domain, e.g. example.com")
    p.add_argument("--format", choices=["text", "json"], default="text",
                   help="Report format. Default: text")
    return p


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    logging.basicConfig(level=logging.INFO,
                        format="%(asctime)s %(levelname)s %(message)s")

    if not args.domain:
        log.error("No domain given. Example: cloud_provider.py example.com")
        return 2

    result = analyze(args.domain)

    if args.format == "json":
        print(json.dumps(result, indent=2))
        return 0

    if not result["ip"]:
        print(f"Could not find IP address for {args.domain}.")
        return 0
    print(f"The IP address of {args.domain} is {result['ip']}")
    if result["org"]:
        print(f"The organization owning the IP is: {result['org']}")
        if result["cloud_provider"]:
            print("The IP address belongs to a major cloud provider.")
        else:
            print("The IP address does not belong to a known major cloud provider.")
    else:
        print("Could not retrieve WHOIS information.")
    return 0


if __name__ == "__main__":
    sys.exit(main())

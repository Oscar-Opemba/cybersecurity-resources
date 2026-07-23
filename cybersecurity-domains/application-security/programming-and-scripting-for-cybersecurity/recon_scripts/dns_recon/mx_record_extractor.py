#!/usr/bin/env python3
"""mx_record_extractor — list a domain's MX records.

Hardened from the original teaching demo, which had a HARDCODED
``get_mx_record('websploit.org')`` call and printed as it went. Now takes the
domain as a CLI argument, returns structured records, and injects the resolver
so the logic is unit-testable without DNS.

See LEGAL.md at the repository root.
"""

from __future__ import annotations

import argparse
import json
import logging
import sys

log = logging.getLogger("mx_record_extractor")


class MxError(Exception):
    """Raised for resolver-level failures (NXDOMAIN, timeout, etc.)."""


def _default_resolver(domain: str):
    """Return a list of (exchange, preference) tuples via dnspython."""
    import dns.resolver

    try:
        answer = dns.resolver.resolve(domain, "MX")
    except dns.resolver.NoAnswer:
        return []
    except dns.resolver.NXDOMAIN as exc:
        raise MxError(f"the domain {domain} does not exist") from exc
    except Exception as exc:  # noqa: BLE001 - surface as a clean MxError
        raise MxError(f"DNS lookup failed: {exc}") from exc
    return [(r.exchange.to_text(), int(r.preference)) for r in answer]


def get_mx_records(domain: str, resolver=None) -> list[dict]:
    """Return MX records as ``[{'exchange':.., 'preference':..}]`` sorted by
    preference. ``resolver`` is injectable for testing.
    """
    if resolver is None:
        resolver = _default_resolver
    records = [
        {"exchange": exch, "preference": pref}
        for exch, pref in resolver(domain)
    ]
    return sorted(records, key=lambda r: r["preference"])


def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        prog="mx_record_extractor",
        description="List the MX records for a domain.",
        epilog="Authorized use only. See LEGAL.md.",
    )
    p.add_argument("domain", nargs="?", help="Domain to query, e.g. example.com")
    p.add_argument("--format", choices=["text", "json"], default="text",
                   help="Report format. Default: text")
    return p


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    logging.basicConfig(level=logging.INFO,
                        format="%(asctime)s %(levelname)s %(message)s")

    if not args.domain:
        log.error("No domain given. Example: mx_record_extractor.py example.com")
        return 2

    try:
        records = get_mx_records(args.domain)
    except MxError as exc:
        log.error("%s", exc)
        return 4

    if args.format == "json":
        print(json.dumps({"domain": args.domain, "mx": records}, indent=2))
    elif not records:
        print(f"No MX records found for {args.domain}.")
    else:
        for r in records:
            print(f"MX Record: {r['exchange']} with priority {r['preference']}")
    return 0


if __name__ == "__main__":
    sys.exit(main())

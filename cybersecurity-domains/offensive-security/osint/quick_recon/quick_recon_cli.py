#!/usr/bin/env python3
"""quick_recon_cli — hardened raw Google-dork query helper.

Original CLI by Adnane X Tebbaa. Unlike ``quick_recon.py`` (which is domain
scoped), this runs an arbitrary dork query, so it cannot be constrained by a
domain scope file. It therefore requires an explicit authorization
acknowledgement and confirms before running.

AUTHORIZED USE ONLY. See LEGAL.md at the repository root.
"""

from __future__ import annotations

import argparse
import logging
import sys

from safety import RateLimiter, confirm

log = logging.getLogger("quick_recon")


def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        prog="quick_recon_cli",
        description="Run a single raw Google-dork query (authorized use only).",
    )
    p.add_argument("query", nargs="?", help="The dork query to run.")
    p.add_argument("--pause", type=float, default=2.0,
                   help="Seconds between requests. Default: 2.0")
    p.add_argument("--yes", action="store_true",
                   help="Skip the confirmation prompt (automation).")
    return p


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    logging.basicConfig(level=logging.INFO,
                        format="%(asctime)s %(levelname)s %(message)s")

    query = args.query or input("[+] Set Query : ").strip()
    if not query:
        log.error("Empty query.")
        return 2

    if not confirm(
        f"Run raw dork query {query!r}? Only do this for authorized research.",
        assume_yes=args.yes,
    ):
        log.error("Aborted by operator.")
        return 1

    try:
        from googlesearch import search
    except ImportError:
        log.error("googlesearch not installed. pip install -r requirements.txt")
        return 2

    limiter = RateLimiter(min_interval=args.pause)
    log.info("Running...")
    try:
        for url in search(query, num=30, stop=90, pause=args.pause):
            limiter.wait()
            print(url)
    except KeyboardInterrupt:
        log.warning("Interrupted by user.")
        return 1
    except Exception as exc:  # noqa: BLE001
        log.error("Search failed: %s", exc)
        return 4
    return 0


if __name__ == "__main__":
    sys.exit(main())

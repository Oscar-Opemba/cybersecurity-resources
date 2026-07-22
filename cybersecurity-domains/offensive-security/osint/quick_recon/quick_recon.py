#!/usr/bin/env python3
"""quick_recon — safe-by-default OSINT dork recon for an authorized target.

Originally by Adnane X Tebbaa (https://github.com/adnane-x-tebbaa/quick_recon).
Hardened for authorized engagement use: explicit scope enforcement, dry-run
preview, rate limiting, retries, structured logging and machine-readable
reports.

AUTHORIZED USE ONLY. Run this only against domains you own or are explicitly
authorized to test. See LEGAL.md at the repository root.
"""

from __future__ import annotations

import argparse
import logging
import sys
from datetime import datetime, timezone
from pathlib import Path

from recon_lib import run_recon
from report import Report
from safety import RateLimiter, Scope, ScopeError, confirm

log = logging.getLogger("quick_recon")


def _real_search(pause: float):
    """Return a SearchFn backed by the googlesearch library.

    Imported lazily so that --dry-run and --help work (and unit tests run)
    without the optional scraping dependency installed.
    """
    try:
        from googlesearch import search as google_search
    except ImportError:  # pragma: no cover - depends on optional dep
        log.error(
            "The 'googlesearch' library is not installed. "
            "Install requirements first: pip install -r requirements.txt"
        )
        raise

    def search(query: str):
        # num/stop bound the result volume; pause spaces out Google requests.
        return google_search(query, num=30, stop=60, pause=pause)

    return search


def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        prog="quick_recon",
        description="Safe-by-default OSINT dork recon for an AUTHORIZED target.",
        epilog="Authorized use only. See LEGAL.md.",
    )
    p.add_argument("target", nargs="?", help="Target domain, e.g. example.com")
    p.add_argument(
        "--scope-file",
        required=False,
        help="Path to a scope allow-list (one domain per line). "
        "REQUIRED unless --i-am-authorized is given.",
    )
    p.add_argument(
        "--i-am-authorized",
        action="store_true",
        help="Assert authorization without a scope file. The target still "
        "must be confirmed. Use only when you cannot supply a scope file.",
    )
    p.add_argument(
        "--dry-run",
        action="store_true",
        help="Print exactly what would be queried and exit without any "
        "network activity.",
    )
    p.add_argument(
        "--yes",
        action="store_true",
        help="Skip the interactive confirmation prompt (for automation).",
    )
    p.add_argument(
        "--pause",
        type=float,
        default=2.0,
        help="Seconds between Google requests (rate limit). Default: 2.0",
    )
    p.add_argument(
        "--retries",
        type=int,
        default=2,
        help="Retries per check on transient failure. Default: 2",
    )
    p.add_argument(
        "--output",
        help="Write the report to this file (format from --format).",
    )
    p.add_argument(
        "--format",
        choices=["text", "json", "csv"],
        default="text",
        help="Report format. Default: text",
    )
    p.add_argument(
        "-v", "--verbose", action="store_true", help="Verbose (DEBUG) logging."
    )
    return p


def resolve_scope(args) -> Scope | None:
    """Return the active Scope, or None when --i-am-authorized is used."""
    if args.scope_file:
        return Scope.from_file(args.scope_file)
    if args.i_am_authorized:
        return None
    raise ScopeError(
        "no scope provided. Pass --scope-file <file> (recommended) or "
        "--i-am-authorized to assert authorization explicitly."
    )


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    logging.basicConfig(
        level=logging.DEBUG if args.verbose else logging.INFO,
        format="%(asctime)s %(levelname)s %(message)s",
    )

    if not args.target:
        log.error("No target given. Example: quick_recon.py example.com "
                  "--scope-file scope.txt")
        return 2

    # --- Scope enforcement (safety rail) ---------------------------------
    try:
        scope = resolve_scope(args)
    except ScopeError as exc:
        log.error("Scope error: %s", exc)
        return 2

    if scope is not None:
        try:
            target = scope.check(args.target)
        except ScopeError as exc:
            log.error("Refusing to run: %s", exc)
            return 3
        scope_domains = scope.domains
    else:
        from safety import normalize_domain
        try:
            target = normalize_domain(args.target)
        except ValueError as exc:
            log.error("Invalid target: %s", exc)
            return 2
        scope_domains = [f"{target} (asserted via --i-am-authorized)"]
        log.warning("Running without a scope file against %s", target)

    # --- Confirmation gate (safety rail) ---------------------------------
    action = "PREVIEW (dry-run)" if args.dry_run else "run live OSINT queries"
    if not confirm(
        f"About to {action} against '{target}'. Are you authorized?",
        assume_yes=args.yes,
    ):
        log.error("Aborted by operator.")
        return 1

    # --- Run --------------------------------------------------------------
    report = Report(
        target=target,
        scope=scope_domains,
        started_at=datetime.now(timezone.utc).isoformat(),
        dry_run=args.dry_run,
    )
    limiter = RateLimiter(min_interval=args.pause)
    search = None if args.dry_run else _real_search(args.pause)

    try:
        run_recon(
            target,
            search,
            report,
            limiter=limiter,
            dry_run=args.dry_run,
            retries=args.retries,
        )
    except KeyboardInterrupt:
        log.warning("Interrupted by user — writing partial report.")
    finally:
        report.finished_at = datetime.now(timezone.utc).isoformat()

    # --- Output -----------------------------------------------------------
    rendered = {
        "text": report.to_text,
        "json": report.to_json,
        "csv": report.to_csv,
    }[args.format]()

    if args.output:
        Path(args.output).write_text(rendered, encoding="utf-8")
        log.info("Report written to %s", args.output)
    else:
        print(rendered)

    return 0


if __name__ == "__main__":
    sys.exit(main())

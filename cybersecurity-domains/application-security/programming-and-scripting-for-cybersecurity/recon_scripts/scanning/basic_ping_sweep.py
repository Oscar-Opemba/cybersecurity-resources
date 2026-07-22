#!/usr/bin/env python3
"""basic_ping_sweep — safe-by-default ICMP host-discovery sweep.

Originally a teaching demo with a HARDCODED 10.6.6.0/24 target and no scope
check. Hardened for engagement use: the target is a required argument,
EVERY host in the expanded range must be in scope before anything runs,
plus dry-run, confirmation, bounded concurrency, rate limiting and
structured reports.

A ping sweep contacts many hosts. Run it only against ranges you own or are
explicitly authorized to test. See LEGAL.md at the repository root.
"""

from __future__ import annotations

import argparse
import logging
import sys
from datetime import datetime, timezone
from pathlib import Path

from scanner_lib import MAX_CONCURRENCY, RateLimiter, Scope, ScopeError
from sweep_lib import (
    SweepError,
    SweepReport,
    check_all_in_scope,
    expand_targets,
    run_sweep,
)

log = logging.getLogger("basic_ping_sweep")


def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        prog="basic_ping_sweep",
        description="Safe-by-default ICMP host-discovery sweep (authorized use).",
        epilog="Authorized use only. See LEGAL.md.",
    )
    p.add_argument(
        "target", nargs="?",
        help="CIDR (10.6.6.0/24), single IP, or range (10.6.6.1-10.6.6.20).",
    )
    p.add_argument(
        "--scope-file",
        help="Allow-list of authorized IPs/CIDRs (one per line). REQUIRED "
        "unless --i-am-authorized is given.",
    )
    p.add_argument(
        "--i-am-authorized", action="store_true",
        help="Assert authorization without a scope file (still confirmed).",
    )
    p.add_argument(
        "--dry-run", action="store_true",
        help="Show the sweep plan and exit — no packets sent.",
    )
    p.add_argument(
        "--yes", action="store_true",
        help="Skip the interactive confirmation prompt (automation).",
    )
    p.add_argument(
        "--concurrency", type=int, default=32,
        help=f"Parallel ping workers (1-{MAX_CONCURRENCY}). Use 1 for the "
        "original sequential behaviour. Default: 32",
    )
    p.add_argument(
        "--rate", type=float, default=0.0,
        help="Max pings per second across all workers (0 = unbounded by rate).",
    )
    p.add_argument(
        "--timeout", type=float, default=1.0,
        help="Per-ping timeout in seconds. Default: 1.0",
    )
    p.add_argument(
        "--format", choices=["text", "json", "csv"], default="text",
        help="Report format. Default: text",
    )
    p.add_argument("--output", help="Write the report to this file.")
    p.add_argument("-v", "--verbose", action="store_true", help="DEBUG logging.")
    return p


def resolve_scope(args) -> Scope | None:
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
        log.error("No target given. Example: basic_ping_sweep.py 10.6.6.0/24 "
                  "--scope-file scope.txt")
        return 2

    # --- Expand the target range ------------------------------------------
    try:
        hosts = expand_targets(args.target)
    except SweepError as exc:
        log.error("Invalid target: %s", exc)
        return 2

    # --- Scope enforcement over the WHOLE range (safety rail) -------------
    try:
        scope = resolve_scope(args)
    except ScopeError as exc:
        log.error("Scope error: %s", exc)
        return 2

    if scope is not None:
        try:
            check_all_in_scope(hosts, scope)
        except ScopeError as exc:
            log.error("Refusing to sweep: %s", exc)
            return 3
        scope_desc = [str(n) for n in scope.networks] + scope.hostnames
    else:
        scope_desc = [f"{args.target} (asserted via --i-am-authorized)"]
        log.warning("Sweeping without a scope file: %s (%d hosts)",
                    args.target, len(hosts))

    # --- Confirmation gate (safety rail) ---------------------------------
    action = "PREVIEW (dry-run)" if args.dry_run else "ICMP-sweep"
    if not args.yes:
        answer = input(
            f"About to {action} {len(hosts)} host(s) in '{args.target}'. "
            "Are you authorized? [y/N]: "
        ).strip().lower()
        if answer not in {"y", "yes"}:
            log.error("Aborted by operator.")
            return 1

    # --- Run --------------------------------------------------------------
    report = SweepReport(
        target=args.target,
        scope=scope_desc,
        started_at=datetime.now(timezone.utc).isoformat(),
        dry_run=args.dry_run,
    )
    limiter = RateLimiter(min_interval=(1.0 / args.rate) if args.rate > 0 else 0.0)

    try:
        run_sweep(
            hosts, report,
            concurrency=args.concurrency,
            timeout=args.timeout,
            rate_limiter=limiter,
            dry_run=args.dry_run,
        )
    except KeyboardInterrupt:
        log.warning("Interrupted by user — writing partial report.")
    finally:
        report.finished_at = datetime.now(timezone.utc).isoformat()

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

#!/usr/bin/env python3
"""quick_scanner — safe-by-default TCP port scanner for an AUTHORIZED host.

Originally by Omar Santos (@santosomar) as a teaching demo. Hardened for
engagement use: explicit scope enforcement, dry-run, confirmation, bounded
concurrency with rate limiting, graceful failure, and structured reports.

A port scan CONTACTS the target host. Run this only against systems you own
or are explicitly authorized to test. See LEGAL.md at the repository root.
"""

from __future__ import annotations

import argparse
import logging
import sys
from datetime import datetime, timezone
from pathlib import Path

from scanner_lib import (
    MAX_CONCURRENCY,
    RateLimiter,
    ScanReport,
    Scope,
    ScopeError,
    normalize_target,
    parse_ports,
    run_scan,
)

log = logging.getLogger("quick_scanner")


def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        prog="quick_scanner",
        description="Safe-by-default TCP port scanner for an AUTHORIZED host.",
        epilog="Authorized use only. See LEGAL.md.",
    )
    p.add_argument("target", nargs="?", help="Target IP or hostname.")
    p.add_argument(
        "--ports", default="1-1024",
        help="Ports to scan: '1-1024', '22,80,443', '22-25,443'. "
        "Default: 1-1024",
    )
    p.add_argument(
        "--scope-file",
        help="Allow-list of authorized IPs/CIDRs/hostnames (one per line). "
        "REQUIRED unless --i-am-authorized is given.",
    )
    p.add_argument(
        "--i-am-authorized", action="store_true",
        help="Assert authorization without a scope file (target still "
        "confirmed).",
    )
    p.add_argument(
        "--dry-run", action="store_true",
        help="Show the scan plan and exit — no resolution, no connections.",
    )
    p.add_argument(
        "--yes", action="store_true",
        help="Skip the interactive confirmation prompt (automation).",
    )
    p.add_argument(
        "--concurrency", type=int, default=16,
        help=f"Parallel connection workers (1-{MAX_CONCURRENCY}). Use 1 for "
        "the original sequential behaviour. Default: 16",
    )
    p.add_argument(
        "--rate", type=float, default=0.0,
        help="Max connections per second across all workers (0 = unlimited "
        "but still bounded by --concurrency). Default: 0",
    )
    p.add_argument(
        "--timeout", type=float, default=1.0,
        help="Per-connection timeout in seconds. Default: 1.0",
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
        log.error("No target given. Example: quick_scanner.py 10.0.0.5 "
                  "--ports 1-1024 --scope-file scope.txt")
        return 2

    try:
        ports = parse_ports(args.ports)
    except ValueError as exc:
        log.error("Invalid --ports: %s", exc)
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
            log.error("Refusing to scan: %s", exc)
            return 3
        scope_desc = [str(n) for n in scope.networks] + scope.hostnames
    else:
        try:
            target = normalize_target(args.target)
        except ValueError as exc:
            log.error("Invalid target: %s", exc)
            return 2
        scope_desc = [f"{target} (asserted via --i-am-authorized)"]
        log.warning("Scanning without a scope file against %s", target)

    # --- Confirmation gate (safety rail) ---------------------------------
    action = "PREVIEW (dry-run)" if args.dry_run else (
        f"scan {len(ports)} port(s) on"
    )
    if not args.yes:
        answer = input(
            f"About to {action} '{target}'. Are you authorized? [y/N]: "
        ).strip().lower()
        if answer not in {"y", "yes"}:
            log.error("Aborted by operator.")
            return 1

    # --- Run --------------------------------------------------------------
    report = ScanReport(
        target=target,
        scope=scope_desc,
        started_at=datetime.now(timezone.utc).isoformat(),
        dry_run=args.dry_run,
    )
    limiter = RateLimiter(min_interval=(1.0 / args.rate) if args.rate > 0 else 0.0)

    try:
        run_scan(
            target, ports, report,
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

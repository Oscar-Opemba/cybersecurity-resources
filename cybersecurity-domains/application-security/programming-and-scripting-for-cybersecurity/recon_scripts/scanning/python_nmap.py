#!/usr/bin/env python3
"""python_nmap — safe-by-default nmap wrapper for AUTHORIZED targets.

Originally by Omar Santos (@santosomar). The original had a Python-3 bug
(`print(...) % (host)` raises TypeError) and no scope check. Hardened here:
scope enforcement over the whole target range, dry-run, confirmation,
structured reports, and a testable, injectable scan function.

An nmap scan contacts the target host(s). Run this only against systems you
own or are explicitly authorized to test. See LEGAL.md at the repository root.
"""

from __future__ import annotations

import argparse
import logging
import sys
from datetime import datetime, timezone
from pathlib import Path

from nmap_lib import NmapReport, run_nmap
from scanner_lib import Scope, ScopeError, parse_ports
from sweep_lib import SweepError, check_all_in_scope, expand_targets

log = logging.getLogger("python_nmap")


def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        prog="python_nmap",
        description="Safe-by-default nmap wrapper for AUTHORIZED targets.",
        epilog="Authorized use only. See LEGAL.md.",
    )
    p.add_argument(
        "target", nargs="?",
        help="CIDR, single IP, or range (10.0.0.1-10.0.0.20).",
    )
    p.add_argument(
        "--ports", default="1-1024",
        help="Ports: '1-1024', '22,80,443'. Default: 1-1024",
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
        help="Show the scan plan and exit — nmap is not invoked.",
    )
    p.add_argument(
        "--yes", action="store_true",
        help="Skip the interactive confirmation prompt (automation).",
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
        log.error("No target given. Example: python_nmap.py 10.0.0.5 "
                  "--ports 22,80,443 --scope-file scope.txt")
        return 2

    # --- Expand + validate ports -----------------------------------------
    try:
        hosts = expand_targets(args.target)
    except SweepError as exc:
        log.error("Invalid target: %s", exc)
        return 2
    try:
        ports_list = parse_ports(args.ports)
    except ValueError as exc:
        log.error("Invalid --ports: %s", exc)
        return 2
    ports_arg = ",".join(str(p) for p in ports_list)

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
            log.error("Refusing to scan: %s", exc)
            return 3
        scope_desc = [str(n) for n in scope.networks] + scope.hostnames
    else:
        scope_desc = [f"{args.target} (asserted via --i-am-authorized)"]
        log.warning("Scanning without a scope file: %s (%d hosts)",
                    args.target, len(hosts))

    # --- Confirmation gate (safety rail) ---------------------------------
    action = "PREVIEW (dry-run)" if args.dry_run else "nmap-scan"
    if not args.yes:
        answer = input(
            f"About to {action} {len(hosts)} host(s) in '{args.target}' "
            f"(ports {args.ports}). Are you authorized? [y/N]: "
        ).strip().lower()
        if answer not in {"y", "yes"}:
            log.error("Aborted by operator.")
            return 1

    # --- Run --------------------------------------------------------------
    report = NmapReport(
        target=args.target,
        scope=scope_desc,
        started_at=datetime.now(timezone.utc).isoformat(),
        dry_run=args.dry_run,
    )
    try:
        run_nmap(hosts, ports_arg, report, dry_run=args.dry_run)
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

    # Signal backend failure (e.g. nmap missing) with a non-zero code.
    if report.errors and not report.dry_run and not report.results:
        return 4
    return 0


if __name__ == "__main__":
    sys.exit(main())

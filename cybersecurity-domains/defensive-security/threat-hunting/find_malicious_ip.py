#!/usr/bin/env python3
"""find_malicious_ip — flag known-bad IPs appearing in log files.

Hardened from the original teaching demo, which HARDCODED both the malicious
IP list and the log path ('path/to/your/logfile.log') and ran at import time
(so it could never actually work). Now: a real CLI, an IOC list loaded from a
file, all IPs per line matched (not just the first), structured output with
line numbers, and unit tests. Reads local files only — no network.

A defensive log-triage helper. See LEGAL.md at the repository root.
"""

from __future__ import annotations

import argparse
import csv
import io
import json
import logging
import re
import sys
from dataclasses import asdict, dataclass, field

log = logging.getLogger("find_malicious_ip")

IP_RE = re.compile(r"\b(?:[0-9]{1,3}\.){3}[0-9]{1,3}\b")


@dataclass
class Match:
    ip: str
    line_number: int
    line: str


@dataclass
class Result:
    source: str
    ioc_count: int = 0
    matches: list[Match] = field(default_factory=list)

    def to_dict(self) -> dict:
        return asdict(self)

    def to_json(self, indent: int = 2) -> str:
        return json.dumps(self.to_dict(), indent=indent)

    def to_csv(self) -> str:
        buf = io.StringIO()
        w = csv.writer(buf)
        w.writerow(["ip", "line_number", "line"])
        for m in self.matches:
            w.writerow([m.ip, m.line_number, m.line])
        return buf.getvalue()

    def to_text(self) -> str:
        lines = [f"Source: {self.source}", f"IOCs loaded: {self.ioc_count}",
                 f"Matches: {len(self.matches)}"]
        for m in self.matches:
            lines.append(f"  line {m.line_number}: {m.ip}  |  {m.line}")
        if not self.matches:
            lines.append("\nNo known-bad IPs found. (Clean result.)")
        return "\n".join(lines)


def load_iocs(path: str) -> set[str]:
    """Load malicious IPs from a file: one per line, '#' comments allowed."""
    iocs: set[str] = set()
    with open(path, encoding="utf-8") as fh:
        for line in fh:
            entry = line.split("#", 1)[0].strip()
            if entry:
                iocs.add(entry)
    return iocs


def search_lines(lines, iocs: set[str], source: str = "<input>") -> Result:
    """Scan an iterable of log lines for any IP present in ``iocs``."""
    result = Result(source=source, ioc_count=len(iocs))
    for n, line in enumerate(lines, start=1):
        for ip in IP_RE.findall(line):
            if ip in iocs:
                result.matches.append(
                    Match(ip=ip, line_number=n, line=line.rstrip("\n"))
                )
    return result


def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        prog="find_malicious_ip",
        description="Flag known-bad IPs appearing in a log file.",
        epilog="Authorized use only. See LEGAL.md.",
    )
    p.add_argument("logfile", nargs="?", help="Path to the log file to scan.")
    p.add_argument("--ioc-file", help="File of malicious IPs (one per line).")
    p.add_argument("--ip", action="append", default=None, metavar="IP",
                   help="Add a malicious IP inline (repeatable).")
    p.add_argument("--format", choices=["text", "json", "csv"], default="text",
                   help="Report format. Default: text")
    p.add_argument("--output", help="Write the report to this file.")
    return p


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    logging.basicConfig(level=logging.INFO,
                        format="%(asctime)s %(levelname)s %(message)s")

    if not args.logfile:
        log.error("No log file given. Example: find_malicious_ip.py auth.log "
                  "--ioc-file bad_ips.txt")
        return 2

    iocs: set[str] = set(args.ip or [])
    if args.ioc_file:
        try:
            iocs |= load_iocs(args.ioc_file)
        except OSError as exc:
            log.error("Could not read IOC file: %s", exc)
            return 2
    if not iocs:
        log.error("No IOCs provided. Use --ioc-file and/or --ip.")
        return 2

    try:
        with open(args.logfile, encoding="utf-8", errors="replace") as fh:
            result = search_lines(fh, iocs, source=args.logfile)
    except OSError as exc:
        log.error("Could not read log file: %s", exc)
        return 2

    rendered = {
        "text": result.to_text,
        "json": result.to_json,
        "csv": result.to_csv,
    }[args.format]()

    if args.output:
        with open(args.output, "w", encoding="utf-8") as fh:
            fh.write(rendered)
        log.info("Report written to %s", args.output)
    else:
        print(rendered)
    return 0


if __name__ == "__main__":
    sys.exit(main())

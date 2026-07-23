#!/usr/bin/env python3
"""sensitive_file_scanner — find potentially sensitive files in a directory tree.

Hardened from the original teaching demo: a real CLI, structured output
(text/JSON/CSV), safe traversal (symlinks are NOT followed by default, so the
scan can't escape the target tree or loop), graceful handling of permission
errors, and unit tests. It reads the local filesystem only — no network.

Use it to audit systems you are authorized to assess. See LEGAL.md.
"""

from __future__ import annotations

import argparse
import csv
import fnmatch
import io
import json
import logging
import os
import sys
from dataclasses import asdict, dataclass, field

log = logging.getLogger("sensitive_file_scanner")

DEFAULT_EXTENSIONS = [".key", ".pem", ".pgp", ".p12", ".pfx", ".csv"]
DEFAULT_PATTERNS = ["*password*", "*secret*", "*private*", "*confidential*"]


@dataclass
class Finding:
    path: str
    reason: str  # e.g. "pattern:*secret*" or "extension:.pem"


@dataclass
class ScanResult:
    directory: str
    findings: list[Finding] = field(default_factory=list)
    errors: list[str] = field(default_factory=list)

    def to_dict(self) -> dict:
        return asdict(self)

    def to_json(self, indent: int = 2) -> str:
        return json.dumps(self.to_dict(), indent=indent)

    def to_csv(self) -> str:
        buf = io.StringIO()
        w = csv.writer(buf)
        w.writerow(["path", "reason"])
        for f in self.findings:
            w.writerow([f.path, f.reason])
        return buf.getvalue()

    def to_text(self) -> str:
        lines = [f"Scanned: {self.directory}",
                 f"Findings: {len(self.findings)}"]
        for f in self.findings:
            lines.append(f"  [{f.reason}] {f.path}")
        if self.errors:
            lines.append(f"\nErrors ({len(self.errors)}):")
            lines.extend(f"  ! {e}" for e in self.errors)
        if not self.findings and not self.errors:
            lines.append("\nNo sensitive files found. (Clean result.)")
        return "\n".join(lines)


def match_reason(
    file_name: str,
    extensions: list[str],
    patterns: list[str],
) -> str | None:
    """Return the reason a file is sensitive, or None if it is not."""
    lowered = file_name.lower()
    for pattern in patterns:
        if fnmatch.fnmatch(lowered, pattern.lower()):
            return f"pattern:{pattern}"
    _, ext = os.path.splitext(file_name)
    if ext.lower() in [e.lower() for e in extensions]:
        return f"extension:{ext.lower()}"
    return None


def scan_directory(
    directory: str,
    *,
    extensions: list[str] | None = None,
    patterns: list[str] | None = None,
    follow_symlinks: bool = False,
) -> ScanResult:
    """Walk ``directory`` and collect sensitive-file findings.

    Symlinks are not followed by default (prevents escaping the tree and
    directory loops). Permission errors are recorded, not raised.
    """
    extensions = DEFAULT_EXTENSIONS if extensions is None else extensions
    patterns = DEFAULT_PATTERNS if patterns is None else patterns
    result = ScanResult(directory=directory)

    def on_error(exc: OSError) -> None:
        result.errors.append(f"{getattr(exc, 'filename', '?')}: {exc}")

    for root, _dirs, files in os.walk(
        directory, followlinks=follow_symlinks, onerror=on_error
    ):
        for name in files:
            reason = match_reason(name, extensions, patterns)
            if reason:
                result.findings.append(
                    Finding(path=os.path.join(root, name), reason=reason)
                )
    return result


def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        prog="sensitive_file_scanner",
        description="Scan a directory tree for potentially sensitive files.",
        epilog="Authorized use only. See LEGAL.md.",
    )
    p.add_argument("directory", nargs="?", help="Directory to scan.")
    p.add_argument("--extension", action="append", default=None,
                   metavar="EXT", help="Add a sensitive extension (repeatable), "
                   "e.g. --extension .env")
    p.add_argument("--pattern", action="append", default=None,
                   metavar="GLOB", help="Add a sensitive filename glob "
                   "(repeatable), e.g. --pattern '*token*'")
    p.add_argument("--follow-symlinks", action="store_true",
                   help="Follow symlinks (off by default for safety).")
    p.add_argument("--format", choices=["text", "json", "csv"], default="text",
                   help="Report format. Default: text")
    p.add_argument("--output", help="Write the report to this file.")
    p.add_argument("-v", "--verbose", action="store_true", help="DEBUG logging.")
    return p


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    logging.basicConfig(
        level=logging.DEBUG if args.verbose else logging.INFO,
        format="%(asctime)s %(levelname)s %(message)s",
    )

    if not args.directory:
        log.error("No directory given. Example: sensitive_file_scanner.py /etc")
        return 2
    if not os.path.isdir(args.directory):
        log.error("Not a valid directory: %s", args.directory)
        return 2

    extensions = DEFAULT_EXTENSIONS + (args.extension or [])
    patterns = DEFAULT_PATTERNS + (args.pattern or [])

    log.info("Scanning %s for sensitive files...", args.directory)
    result = scan_directory(
        args.directory,
        extensions=extensions,
        patterns=patterns,
        follow_symlinks=args.follow_symlinks,
    )

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

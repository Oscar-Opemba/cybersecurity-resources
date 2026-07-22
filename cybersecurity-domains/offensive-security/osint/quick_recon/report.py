#!/usr/bin/env python3
"""Structured result model for quick_recon.

Keeping results in a typed model (rather than printing as we go) means the
same run can be rendered as human text, JSON, or CSV, and fed into other
tooling. Nothing here performs network activity.
"""

from __future__ import annotations

import csv
import io
import json
from dataclasses import asdict, dataclass, field


@dataclass
class Finding:
    """A single recon result: which check produced it and the URL found."""

    category: str
    url: str


@dataclass
class Report:
    """A full recon run against one target."""

    target: str
    scope: list[str] = field(default_factory=list)
    started_at: str = ""
    finished_at: str = ""
    dry_run: bool = False
    findings: list[Finding] = field(default_factory=list)
    errors: list[str] = field(default_factory=list)

    def add(self, category: str, url: str) -> None:
        self.findings.append(Finding(category=category, url=url))

    def add_error(self, message: str) -> None:
        self.errors.append(message)

    def categories(self) -> dict[str, list[str]]:
        """Group finding URLs by category, preserving first-seen order."""
        grouped: dict[str, list[str]] = {}
        for f in self.findings:
            grouped.setdefault(f.category, []).append(f.url)
        return grouped

    def to_dict(self) -> dict:
        return asdict(self)

    def to_json(self, indent: int = 2) -> str:
        return json.dumps(self.to_dict(), indent=indent)

    def to_csv(self) -> str:
        buf = io.StringIO()
        writer = csv.writer(buf)
        writer.writerow(["target", "category", "url"])
        for f in self.findings:
            writer.writerow([self.target, f.category, f.url])
        return buf.getvalue()

    def to_text(self) -> str:
        lines = [
            "=" * 60,
            f"quick_recon report for: {self.target}",
            f"scope:      {', '.join(self.scope) or '(none)'}",
            f"started:    {self.started_at}",
            f"finished:   {self.finished_at}",
            f"dry-run:    {self.dry_run}",
            f"findings:   {len(self.findings)}",
            f"errors:     {len(self.errors)}",
            "=" * 60,
        ]
        for category, urls in self.categories().items():
            lines.append(f"\n[{category}] ({len(urls)})")
            lines.extend(f"  - {u}" for u in urls)
        if self.errors:
            lines.append("\n[errors]")
            lines.extend(f"  ! {e}" for e in self.errors)
        if not self.findings and not self.errors:
            lines.append("\nNo findings. (This is a clean result, not an error.)")
        return "\n".join(lines)

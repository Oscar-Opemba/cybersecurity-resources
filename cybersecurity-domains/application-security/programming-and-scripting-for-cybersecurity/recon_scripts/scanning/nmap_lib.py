#!/usr/bin/env python3
"""Core logic for the hardened python_nmap wrapper.

Wraps the ``python-nmap`` library (which shells out to the system ``nmap``)
behind an injectable scan function, so the whole module is unit-testable
without invoking nmap or touching a host. Reuses the scope/parsing primitives
from ``scanner_lib``.

Capability note: this performs a *basic* nmap scan of the given ports on the
given hosts. It intentionally does NOT expose nmap's aggressive options (no
custom -sS/-A/NSE arguments) — the hardening pass is about running the
existing basic-scan capability safely, not expanding it.
"""

from __future__ import annotations

import csv
import io
import json
from dataclasses import asdict, dataclass, field
from typing import Callable

# ScanFn(hosts: list[str], ports: str) -> dict[host -> list[(port, state)]]
ScanFn = Callable[[list[str], str], dict]


class NmapError(Exception):
    """Raised when nmap is unavailable or a scan fails."""


def default_scan_fn(hosts: list[str], ports: str) -> dict:
    """Run a basic nmap scan via python-nmap. Imported lazily.

    Returns a mapping of host -> list of (port, state) tuples for TCP ports.
    """
    try:
        import nmap
    except ImportError as exc:  # pragma: no cover - optional dep
        raise NmapError(
            "the python-nmap library is not installed. "
            "Install it with: pip install python-nmap "
            "(and ensure the 'nmap' binary is on PATH)."
        ) from exc

    scanner = nmap.PortScanner()
    try:
        scanner.scan(hosts=" ".join(hosts), ports=ports)
    except Exception as exc:  # noqa: BLE001 - surface as a clean NmapError
        raise NmapError(f"nmap scan failed: {exc}") from exc

    results: dict[str, list[tuple[int, str]]] = {}
    for host in scanner.all_hosts():
        ports_found: list[tuple[int, str]] = []
        host_data = scanner[host]
        if "tcp" in host_data:
            for port in sorted(host_data["tcp"]):
                ports_found.append((port, host_data["tcp"][port]["state"]))
        results[host] = ports_found
    return results


@dataclass
class NmapReport:
    target: str
    ports: str = ""
    hosts_total: int = 0
    scope: list[str] = field(default_factory=list)
    started_at: str = ""
    finished_at: str = ""
    dry_run: bool = False
    # host -> list of {"port": int, "state": str}
    results: dict = field(default_factory=dict)
    errors: list[str] = field(default_factory=list)

    def add_host(self, host: str, ports: list[tuple[int, str]]) -> None:
        self.results[host] = [
            {"port": p, "state": s} for p, s in ports
        ]

    def open_count(self) -> int:
        return sum(
            1
            for ports in self.results.values()
            for entry in ports
            if entry["state"] == "open"
        )

    def to_dict(self) -> dict:
        return asdict(self)

    def to_json(self, indent: int = 2) -> str:
        return json.dumps(self.to_dict(), indent=indent)

    def to_csv(self) -> str:
        buf = io.StringIO()
        w = csv.writer(buf)
        w.writerow(["host", "port", "state"])
        for host, ports in self.results.items():
            for entry in ports:
                w.writerow([host, entry["port"], entry["state"]])
        return buf.getvalue()

    def to_text(self) -> str:
        lines = [
            "=" * 56,
            f"python_nmap report for: {self.target}",
            f"ports:       {self.ports}",
            f"scope:       {', '.join(self.scope) or '(none)'}",
            f"hosts:       {self.hosts_total}",
            f"started:     {self.started_at}",
            f"finished:    {self.finished_at}",
            f"dry-run:     {self.dry_run}",
            "=" * 56,
        ]
        if self.results:
            for host, ports in self.results.items():
                open_ports = [e for e in ports if e["state"] == "open"]
                lines.append(f"\n{host} — {len(open_ports)} open")
                for entry in ports:
                    lines.append(f"  - {entry['port']}/tcp {entry['state']}")
        elif not self.dry_run and not self.errors:
            lines.append("\nNo results. (Clean result, not an error.)")
        if self.errors:
            lines.append("\n[errors]")
            lines.extend(f"  ! {e}" for e in self.errors)
        return "\n".join(lines)


def run_nmap(
    hosts: list[str],
    ports: str,
    report: NmapReport,
    *,
    scan_fn: ScanFn | None = None,
    dry_run: bool = False,
) -> NmapReport:
    """Scan ``ports`` on ``hosts`` into ``report``.

    ``scan_fn`` defaults to the module-level ``default_scan_fn`` resolved at
    call time (so it stays monkeypatchable). Dry-run records the plan and
    invokes no scan.
    """
    if scan_fn is None:
        scan_fn = default_scan_fn
    report.hosts_total = len(hosts)
    report.ports = ports
    if dry_run:
        report.errors.append(
            f"dry-run: would run nmap on {len(hosts)} host(s) "
            f"({hosts[0]} … {hosts[-1]}), ports {ports}"
        )
        return report
    try:
        results = scan_fn(hosts, ports)
    except NmapError as exc:
        report.errors.append(str(exc))
        return report
    for host, found in results.items():
        report.add_host(host, found)
    return report

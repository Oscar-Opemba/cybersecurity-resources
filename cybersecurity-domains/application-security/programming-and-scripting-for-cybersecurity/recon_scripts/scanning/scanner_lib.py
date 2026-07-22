#!/usr/bin/env python3
"""Core logic for the hardened quick_scanner TCP port scanner.

Everything here is network-injectable: the TCP connect and the hostname
resolver are passed in, so the whole module is unit-testable without touching
a real host. This module performs no network activity on its own.

Scope model
-----------
A port scan *contacts the target*, so scope is enforced strictly and without
DNS: a scope file lists allowed IPs, CIDRs, and/or exact hostnames. A target
is in scope only if it is an IP inside an allowed network, or an exact
hostname match. Hostnames are never resolved for the scope check (that would
open a DNS-confusion scope bypass) — to scan by hostname, list that hostname
in scope, or scan its IP.
"""

from __future__ import annotations

import csv
import io
import ipaddress
import json
import threading
import time
from concurrent.futures import ThreadPoolExecutor, as_completed
from dataclasses import asdict, dataclass, field
from pathlib import Path

# Hard ceiling on parallelism so the tool can never be turned into an
# accidental DoS with a huge --concurrency value.
MAX_CONCURRENCY = 256


class ScopeError(Exception):
    """Raised when a target is not covered by the active scope."""


class ScanError(Exception):
    """Raised for unrecoverable scan setup problems (e.g. bad host)."""


# --------------------------------------------------------------------------- #
# Target / port parsing
# --------------------------------------------------------------------------- #
def normalize_target(value: str) -> str:
    """Return a cleaned target host (IP literal or lower-cased hostname)."""
    value = (value or "").strip()
    if not value:
        raise ValueError("empty target")
    try:
        return str(ipaddress.ip_address(value))
    except ValueError:
        return value.lower()


def parse_ports(spec: str) -> list[int]:
    """Parse a port spec like '1-1024', '22,80,443' or '22-25,443'.

    Returns a sorted, de-duplicated list of valid ports (1-65535).
    """
    if not spec or not spec.strip():
        raise ValueError("empty port specification")
    ports: set[int] = set()
    for part in spec.split(","):
        part = part.strip()
        if not part:
            continue
        if "-" in part:
            lo_s, hi_s = part.split("-", 1)
            lo, hi = int(lo_s), int(hi_s)
            if lo > hi:
                raise ValueError(f"port range {part!r} is reversed")
            for p in range(lo, hi + 1):
                ports.add(p)
        else:
            ports.add(int(part))
    for p in ports:
        if not (1 <= p <= 65535):
            raise ValueError(f"port {p} out of range 1-65535")
    if not ports:
        raise ValueError("no ports parsed")
    return sorted(ports)


# --------------------------------------------------------------------------- #
# Scope
# --------------------------------------------------------------------------- #
@dataclass
class Scope:
    """Allow-list of authorized scan targets: IPs, CIDRs, exact hostnames."""

    networks: list[ipaddress._BaseNetwork] = field(default_factory=list)
    hostnames: list[str] = field(default_factory=list)

    @classmethod
    def from_entries(cls, entries: list[str]) -> "Scope":
        nets: list[ipaddress._BaseNetwork] = []
        hosts: list[str] = []
        for raw in entries:
            entry = raw.strip()
            if not entry:
                continue
            try:
                nets.append(ipaddress.ip_network(entry, strict=False))
            except ValueError:
                hosts.append(entry.lower())
        return cls(networks=nets, hostnames=hosts)

    @classmethod
    def from_file(cls, path: str | Path) -> "Scope":
        path = Path(path)
        if not path.exists():
            raise ScopeError(f"scope file not found: {path}")
        entries: list[str] = []
        for line in path.read_text(encoding="utf-8").splitlines():
            line = line.split("#", 1)[0].strip()
            if line:
                entries.append(line)
        scope = cls.from_entries(entries)
        if not scope.networks and not scope.hostnames:
            raise ScopeError(f"scope file {path} contains no entries")
        return scope

    def check(self, target: str) -> str:
        """Return the normalized target if in scope, else raise ScopeError."""
        try:
            normalized = normalize_target(target)
        except ValueError as exc:
            raise ScopeError(f"invalid target {target!r}: {exc}") from exc
        try:
            ip = ipaddress.ip_address(normalized)
        except ValueError:
            ip = None
        if ip is not None:
            for net in self.networks:
                if ip in net:
                    return normalized
            raise ScopeError(
                f"IP {normalized} is NOT within any in-scope network: "
                f"{', '.join(str(n) for n in self.networks) or '(none)'}"
            )
        # Hostname target: require an exact scope entry, never resolve DNS.
        if normalized in self.hostnames:
            return normalized
        raise ScopeError(
            f"hostname {normalized!r} is not an exact in-scope entry. "
            "Add it to the scope file, or scan its IP instead."
        )


# --------------------------------------------------------------------------- #
# Rate limiting (thread-safe)
# --------------------------------------------------------------------------- #
class RateLimiter:
    """Thread-safe minimum-interval limiter shared across scan workers."""

    def __init__(self, min_interval: float, sleep=time.sleep, clock=time.monotonic):
        if min_interval < 0:
            raise ValueError("min_interval must be >= 0")
        self.min_interval = float(min_interval)
        self._sleep = sleep
        self._clock = clock
        self._lock = threading.Lock()
        self._next_at: float | None = None

    def wait(self) -> None:
        if self.min_interval == 0:
            return
        with self._lock:
            now = self._clock()
            if self._next_at is None or now >= self._next_at:
                self._next_at = now + self.min_interval
                return
            delay = self._next_at - now
            self._next_at += self.min_interval
        self._sleep(delay)


# --------------------------------------------------------------------------- #
# Report model
# --------------------------------------------------------------------------- #
@dataclass
class ScanReport:
    target: str
    ports_scanned: int = 0
    scope: list[str] = field(default_factory=list)
    started_at: str = ""
    finished_at: str = ""
    dry_run: bool = False
    open_ports: list[int] = field(default_factory=list)
    errors: list[str] = field(default_factory=list)

    def to_dict(self) -> dict:
        return asdict(self)

    def to_json(self, indent: int = 2) -> str:
        return json.dumps(self.to_dict(), indent=indent)

    def to_csv(self) -> str:
        buf = io.StringIO()
        w = csv.writer(buf)
        w.writerow(["target", "port", "state"])
        for p in self.open_ports:
            w.writerow([self.target, p, "open"])
        return buf.getvalue()

    def to_text(self) -> str:
        lines = [
            "=" * 56,
            f"quick_scanner report for: {self.target}",
            f"scope:         {', '.join(self.scope) or '(none)'}",
            f"ports scanned: {self.ports_scanned}",
            f"started:       {self.started_at}",
            f"finished:      {self.finished_at}",
            f"dry-run:       {self.dry_run}",
            "=" * 56,
        ]
        if self.open_ports:
            lines.append(f"\nOpen ports ({len(self.open_ports)}):")
            lines.extend(f"  - {p}/tcp open" for p in self.open_ports)
        elif not self.dry_run and not self.errors:
            lines.append("\nNo open ports found. (Clean result, not an error.)")
        if self.errors:
            lines.append("\n[errors]")
            lines.extend(f"  ! {e}" for e in self.errors)
        return "\n".join(lines)


# --------------------------------------------------------------------------- #
# Scanning
# --------------------------------------------------------------------------- #
def default_connect(host: str, port: int, timeout: float) -> int:
    """Real TCP connect probe. Returns 0 if the port is open."""
    import socket

    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
        sock.settimeout(timeout)
        return sock.connect_ex((host, port))


def default_resolver(host: str) -> None:
    """Raise ScanError if the host cannot be resolved."""
    import socket

    try:
        socket.getaddrinfo(host, None)
    except socket.gaierror as exc:
        raise ScanError(f"could not resolve target {host!r}: {exc}") from exc


def scan_port(host, port, connect, timeout, limiter=None):
    """Probe one port. Returns (port, is_open, error_or_None)."""
    if limiter is not None:
        limiter.wait()
    try:
        rc = connect(host, port, timeout)
        return port, rc == 0, None
    except Exception as exc:  # noqa: BLE001 - one bad port never aborts the scan
        return port, False, f"port {port}: {exc}"


def run_scan(
    host: str,
    ports: list[int],
    report: ScanReport,
    *,
    connect=None,
    resolver=None,
    concurrency: int = 16,
    timeout: float = 1.0,
    rate_limiter: RateLimiter | None = None,
    dry_run: bool = False,
) -> ScanReport:
    """Scan ``ports`` on ``host`` into ``report``.

    Concurrency is clamped to [1, MAX_CONCURRENCY]. In dry-run mode nothing
    is resolved or connected — the plan is recorded and returned. ``connect``
    and ``resolver`` default to the module-level implementations resolved at
    call time (so they stay monkeypatchable in tests).
    """
    if connect is None:
        connect = default_connect
    if resolver is None:
        resolver = default_resolver
    report.ports_scanned = len(ports)
    if dry_run:
        report.errors.append(
            f"dry-run: would scan {len(ports)} port(s) on {host} "
            f"(range {ports[0]}-{ports[-1]})"
        )
        return report

    try:
        resolver(host)
    except ScanError as exc:
        report.errors.append(str(exc))
        return report

    workers = max(1, min(int(concurrency), MAX_CONCURRENCY))
    open_ports: list[int] = []
    with ThreadPoolExecutor(max_workers=workers) as pool:
        futures = [
            pool.submit(scan_port, host, p, connect, timeout, rate_limiter)
            for p in ports
        ]
        for fut in as_completed(futures):
            port, is_open, err = fut.result()
            if is_open:
                open_ports.append(port)
            if err:
                report.errors.append(err)
    report.open_ports = sorted(open_ports)
    return report

#!/usr/bin/env python3
"""Core logic for the hardened basic_ping_sweep host-discovery sweep.

Reuses the safety primitives from ``scanner_lib`` (Scope, RateLimiter) and
adds range expansion and a whole-range scope gate: because a sweep touches
*many* hosts, EVERY expanded host must be in scope before anything runs.

The pinger is injected, so the whole module is unit-testable without sending
a single real packet.
"""

from __future__ import annotations

import csv
import io
import ipaddress
import json
import platform
from concurrent.futures import ThreadPoolExecutor, as_completed
from dataclasses import asdict, dataclass, field

from scanner_lib import MAX_CONCURRENCY, RateLimiter, Scope, ScopeError

# Refuse to expand an absurdly large range by mistake. 65,536 hosts is a /16
# for IPv4 — already very large for a ping sweep; anything bigger is almost
# certainly a fat-fingered target.
MAX_SWEEP_HOSTS = 65536


class SweepError(Exception):
    """Raised for target-expansion / sizing problems."""


def expand_targets(spec: str) -> list[str]:
    """Expand a target spec into a list of host IP strings.

    Accepts a CIDR (``10.6.6.0/24``), a single IP (``10.6.6.5``), or an
    inclusive dashed range (``10.6.6.1-10.6.6.20``). Network/broadcast
    addresses of a CIDR are excluded (hosts only). Raises SweepError if the
    result would exceed MAX_SWEEP_HOSTS.
    """
    spec = (spec or "").strip()
    if not spec:
        raise SweepError("empty target specification")

    hosts: list[str]
    if "-" in spec and "/" not in spec:
        lo_s, hi_s = (p.strip() for p in spec.split("-", 1))
        try:
            lo, hi = ipaddress.ip_address(lo_s), ipaddress.ip_address(hi_s)
        except ValueError as exc:
            raise SweepError(f"invalid range {spec!r}: {exc}") from exc
        if int(hi) < int(lo):
            raise SweepError(f"range {spec!r} is reversed")
        count = int(hi) - int(lo) + 1
        if count > MAX_SWEEP_HOSTS:
            raise SweepError(
                f"range {spec!r} expands to {count} hosts "
                f"(> {MAX_SWEEP_HOSTS}); refine it"
            )
        hosts = [str(ipaddress.ip_address(int(lo) + i)) for i in range(count)]
    else:
        try:
            net = ipaddress.ip_network(spec, strict=False)
        except ValueError as exc:
            raise SweepError(f"invalid target {spec!r}: {exc}") from exc
        if net.num_addresses > MAX_SWEEP_HOSTS:
            raise SweepError(
                f"network {spec!r} has {net.num_addresses} addresses "
                f"(> {MAX_SWEEP_HOSTS}); use a smaller prefix"
            )
        # /32 (or /128) is a single host; hosts() would return empty for it.
        if net.num_addresses == 1:
            hosts = [str(net.network_address)]
        else:
            hosts = [str(ip) for ip in net.hosts()]
    if not hosts:
        raise SweepError(f"target {spec!r} expands to no hosts")
    return hosts


def check_all_in_scope(hosts: list[str], scope: Scope) -> None:
    """Raise ScopeError if ANY host is out of scope, listing offenders."""
    out = []
    for h in hosts:
        try:
            scope.check(h)
        except ScopeError:
            out.append(h)
    if out:
        shown = ", ".join(out[:5]) + ("…" if len(out) > 5 else "")
        raise ScopeError(
            f"{len(out)} of {len(hosts)} target host(s) are NOT in scope "
            f"(e.g. {shown}). Refusing the entire sweep."
        )


@dataclass
class SweepReport:
    target: str
    hosts_total: int = 0
    scope: list[str] = field(default_factory=list)
    started_at: str = ""
    finished_at: str = ""
    dry_run: bool = False
    up: list[str] = field(default_factory=list)
    errors: list[str] = field(default_factory=list)

    @property
    def down_count(self) -> int:
        return self.hosts_total - len(self.up)

    def to_dict(self) -> dict:
        d = asdict(self)
        d["down_count"] = self.down_count
        return d

    def to_json(self, indent: int = 2) -> str:
        return json.dumps(self.to_dict(), indent=indent)

    def to_csv(self) -> str:
        buf = io.StringIO()
        w = csv.writer(buf)
        w.writerow(["host", "state"])
        for h in self.up:
            w.writerow([h, "up"])
        return buf.getvalue()

    def to_text(self) -> str:
        lines = [
            "=" * 56,
            f"basic_ping_sweep report for: {self.target}",
            f"scope:       {', '.join(self.scope) or '(none)'}",
            f"hosts total: {self.hosts_total}",
            f"started:     {self.started_at}",
            f"finished:    {self.finished_at}",
            f"dry-run:     {self.dry_run}",
            "=" * 56,
        ]
        if self.up:
            lines.append(f"\nHosts up ({len(self.up)}):")
            lines.extend(f"  - {h} is up" for h in self.up)
        elif not self.dry_run and not self.errors:
            lines.append("\nNo hosts responded. (Clean result, not an error.)")
        if self.errors:
            lines.append("\n[errors]")
            lines.extend(f"  ! {e}" for e in self.errors)
        return "\n".join(lines)


def default_pinger(ip: str, timeout: float) -> bool:
    """Send one ICMP echo via the system ``ping``. True if the host replied.

    Builds a platform-appropriate command (Linux/macOS/Windows differ on the
    count and timeout flags).
    """
    import subprocess

    system = platform.system().lower()
    if system == "windows":
        cmd = ["ping", "-n", "1", "-w", str(int(timeout * 1000)), ip]
    elif system == "darwin":
        cmd = ["ping", "-c", "1", "-W", str(int(timeout * 1000)), ip]
    else:  # linux and friends
        cmd = ["ping", "-c", "1", "-W", str(max(1, int(timeout))), ip]
    try:
        result = subprocess.run(
            cmd,
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
            timeout=timeout + 5,
        )
        return result.returncode == 0
    except (subprocess.TimeoutExpired, OSError):
        return False


def ping_host(ip, pinger, timeout, limiter=None):
    """Ping one host. Returns (ip, is_up, error_or_None)."""
    if limiter is not None:
        limiter.wait()
    try:
        return ip, bool(pinger(ip, timeout)), None
    except Exception as exc:  # noqa: BLE001 - one bad host never aborts the sweep
        return ip, False, f"{ip}: {exc}"


def run_sweep(
    hosts: list[str],
    report: SweepReport,
    *,
    pinger=None,
    concurrency: int = 32,
    timeout: float = 1.0,
    rate_limiter: RateLimiter | None = None,
    dry_run: bool = False,
) -> SweepReport:
    """Ping every host in ``hosts`` into ``report``.

    Concurrency is clamped to [1, MAX_CONCURRENCY]. Dry-run records the plan
    and sends nothing. ``pinger`` defaults to the module-level
    ``default_pinger`` resolved at call time (so it stays monkeypatchable).
    """
    if pinger is None:
        pinger = default_pinger
    report.hosts_total = len(hosts)
    if dry_run:
        report.errors.append(
            f"dry-run: would ping {len(hosts)} host(s) "
            f"({hosts[0]} … {hosts[-1]})"
        )
        return report

    workers = max(1, min(int(concurrency), MAX_CONCURRENCY))
    up: list[str] = []
    with ThreadPoolExecutor(max_workers=workers) as pool:
        futures = [
            pool.submit(ping_host, h, pinger, timeout, rate_limiter)
            for h in hosts
        ]
        for fut in as_completed(futures):
            ip, is_up, err = fut.result()
            if is_up:
                up.append(ip)
            if err:
                report.errors.append(err)
    report.up = sorted(up, key=lambda x: ipaddress.ip_address(x))
    return report

#!/usr/bin/env python3
"""Safety rails shared by the quick_recon tooling.

This module centralises the "don't accidentally point a recon tool at the
wrong target" logic:

* scope validation against an explicit allow-list (a scope file),
* a dry-run preview mode,
* an interactive confirmation gate,
* a simple rate limiter so we never hammer an upstream service.

None of these functions perform network activity. They are pure/local so
they can be unit-tested without touching live infrastructure.
"""

from __future__ import annotations

import time
from dataclasses import dataclass, field
from pathlib import Path
from urllib.parse import urlparse


class ScopeError(Exception):
    """Raised when a target is not covered by the active scope."""


def normalize_domain(value: str) -> str:
    """Return the bare registrable host for a domain or URL.

    Accepts ``example.com``, ``http://example.com/path`` or
    ``sub.example.com`` and returns a lower-cased host with no scheme,
    port, path or leading ``www.``. Raises ``ValueError`` for input that
    contains no host at all.
    """
    value = (value or "").strip().lower()
    if not value:
        raise ValueError("empty target")
    # Give urlparse a scheme so it treats "example.com/x" as a host+path.
    if "://" not in value:
        value = "//" + value
    host = urlparse(value).hostname or ""
    if not host:
        raise ValueError(f"could not parse a host from {value!r}")
    if host.startswith("www."):
        host = host[4:]
    return host


def _domain_in_scope(target: str, allowed: str) -> bool:
    """True if ``target`` equals ``allowed`` or is a sub-domain of it."""
    target = normalize_domain(target)
    allowed = normalize_domain(allowed)
    return target == allowed or target.endswith("." + allowed)


@dataclass
class Scope:
    """An explicit allow-list of in-scope domains.

    A target is considered in scope if it exactly matches, or is a
    sub-domain of, any entry. This is intentionally strict: there is no
    wildcard expansion and no implicit "all" — an empty scope allows
    nothing.
    """

    domains: list[str] = field(default_factory=list)

    @classmethod
    def from_file(cls, path: str | Path) -> "Scope":
        """Load a scope file: one domain per line, ``#`` comments allowed."""
        path = Path(path)
        if not path.exists():
            raise ScopeError(f"scope file not found: {path}")
        domains: list[str] = []
        for raw in path.read_text(encoding="utf-8").splitlines():
            line = raw.split("#", 1)[0].strip()
            if not line:
                continue
            domains.append(normalize_domain(line))
        if not domains:
            raise ScopeError(f"scope file {path} contains no domains")
        return cls(domains=domains)

    def check(self, target: str) -> str:
        """Return the normalized target if in scope, else raise ScopeError."""
        try:
            normalized = normalize_domain(target)
        except ValueError as exc:
            raise ScopeError(f"invalid target {target!r}: {exc}") from exc
        for allowed in self.domains:
            if _domain_in_scope(normalized, allowed):
                return normalized
        raise ScopeError(
            f"target {normalized!r} is NOT in scope. "
            f"In-scope domains: {', '.join(self.domains)}"
        )


class RateLimiter:
    """Blocking rate limiter enforcing a minimum delay between calls.

    ``min_interval`` is the minimum number of seconds between successive
    ``wait()`` calls. The first call never blocks.
    """

    def __init__(self, min_interval: float, sleep=time.sleep, clock=time.monotonic):
        if min_interval < 0:
            raise ValueError("min_interval must be >= 0")
        self.min_interval = float(min_interval)
        self._sleep = sleep
        self._clock = clock
        self._last: float | None = None

    def wait(self) -> float:
        """Sleep as needed to honour the interval. Returns seconds slept."""
        now = self._clock()
        if self._last is None:
            self._last = now
            return 0.0
        elapsed = now - self._last
        remaining = self.min_interval - elapsed
        slept = 0.0
        if remaining > 0:
            self._sleep(remaining)
            slept = remaining
        self._last = self._clock()
        return slept


def confirm(prompt: str, *, assume_yes: bool = False, input_fn=input) -> bool:
    """Interactive yes/no gate. Returns True only on an explicit yes.

    ``assume_yes`` bypasses the prompt (for non-interactive/automation use
    where the caller has already accepted responsibility).
    """
    if assume_yes:
        return True
    answer = input_fn(f"{prompt} [y/N]: ").strip().lower()
    return answer in {"y", "yes"}

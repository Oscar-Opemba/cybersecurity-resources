#!/usr/bin/env python3
"""Core recon logic for quick_recon.

The Google-dork queries live here as data, and the search itself is injected
so the whole module can be unit-tested with a fake search function — no live
network calls in tests. Each query is run through a rate limiter and wrapped
in retry/backoff so a single transient failure does not abort the run.

NOTE ON THE UPSTREAM MECHANISM: this tool enumerates results by scraping
Google via the third-party ``googlesearch`` library. That mechanism is
inherently brittle (Google actively blocks scraping) and is unchanged from
the original tool — the hardening here is about running it *safely and
predictably*, not about making Google scraping reliable. See README.
"""

from __future__ import annotations

import logging
import time
from dataclasses import dataclass
from typing import Callable, Iterable
from urllib.parse import urlparse

from report import Report
from safety import RateLimiter

log = logging.getLogger("quick_recon")

# SearchFn(query) -> iterable of result URLs. This is the single seam we mock
# in tests and where the real googlesearch library plugs in at runtime.
SearchFn = Callable[[str], Iterable[str]]


@dataclass(frozen=True)
class Check:
    """A named recon check and the dork template that implements it.

    ``template`` is formatted with ``{target}``.
    """

    category: str
    description: str
    template: str

    def query(self, target: str) -> str:
        return self.template.format(target=target)


# The checks preserved from the original quick_recon, expressed as data.
CHECKS: tuple[Check, ...] = (
    Check("subdomains", "Subdomains",
          "site:{target} -www.{target}"),
    Check("subdomains", "Wildcard subdomains",
          "site:*.{target}"),
    Check("sub_subdomains", "Sub-subdomains",
          "site:*.*.{target}"),
    Check("login_pages", "Login pages",
          "inurl:login site:{target}"),
    Check("login_pages", "Signup/register pages",
          "site:{target} inurl:signup | inurl:register | intitle:Signup"),
    Check("directory_listing", "Directory listings",
          "site:{target} intitle:index of"),
    Check("exposed_documents", "Publicly exposed documents",
          "site:{target} ext:doc | ext:docx | ext:odt | ext:pdf | ext:rtf | "
          "ext:sxw | ext:psw | ext:ppt | ext:pptx | ext:pps | ext:csv"),
    Check("wordpress", "WordPress entries",
          "site:{target} inurl:wp- | inurl:wp-content | inurl:plugins | "
          "inurl:uploads | inurl:themes | inurl:download"),
    Check("paste_sites", "Paste-site mentions",
          "site:pastebin.com | site:hastebin.com | site:carbon.now.sh {target}"),
)


def normalize_result(url: str) -> str:
    """Reduce a result URL to scheme://host/ for de-duplication."""
    parsed = urlparse(url)
    if parsed.scheme and parsed.netloc:
        return f"{parsed.scheme}://{parsed.netloc}/"
    return url


def run_check(
    check: Check,
    target: str,
    search: SearchFn,
    *,
    limiter: RateLimiter | None = None,
    retries: int = 2,
    backoff: float = 2.0,
    sleep=time.sleep,
) -> tuple[list[str], list[str]]:
    """Run one check, returning ``(urls, errors)``.

    Applies the rate limiter before the call and retries on exception with
    exponential backoff. A check that keeps failing yields an error string
    rather than raising, so one flaky query never aborts the whole run.
    """
    query = check.query(target)
    errors: list[str] = []
    for attempt in range(retries + 1):
        if limiter is not None:
            limiter.wait()
        try:
            results = list(search(query))
            urls = [normalize_result(u) for u in results]
            # De-dup while preserving order.
            seen: set[str] = set()
            deduped = [u for u in urls if not (u in seen or seen.add(u))]
            return deduped, errors
        except Exception as exc:  # noqa: BLE001 - we deliberately keep going
            msg = f"[{check.category}] query failed (attempt {attempt + 1}): {exc}"
            log.warning(msg)
            if attempt < retries:
                sleep(backoff * (2 ** attempt))
            else:
                errors.append(msg)
    return [], errors


def run_recon(
    target: str,
    search: SearchFn,
    report: Report,
    *,
    checks: Iterable[Check] = CHECKS,
    limiter: RateLimiter | None = None,
    dry_run: bool = False,
    retries: int = 2,
    sleep=time.sleep,
) -> Report:
    """Run all checks against ``target``, recording into ``report``.

    In dry-run mode no search is performed: each check's resolved query is
    logged and recorded so the operator can review exactly what *would* run.
    """
    for check in checks:
        query = check.query(target)
        if dry_run:
            log.info("DRY-RUN would query [%s]: %s", check.category, query)
            report.add_error(f"dry-run: skipped [{check.category}] {query}")
            continue
        log.info("Running check [%s]: %s", check.category, check.description)
        urls, errors = run_check(
            check, target, search, limiter=limiter, retries=retries, sleep=sleep
        )
        for url in urls:
            report.add(check.category, url)
        for err in errors:
            report.add_error(err)
    return report

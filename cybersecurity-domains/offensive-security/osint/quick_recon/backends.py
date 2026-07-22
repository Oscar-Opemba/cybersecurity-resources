#!/usr/bin/env python3
"""Search backends for quick_recon.

A *backend* is a factory that returns a ``SearchFn`` — a callable
``query -> iterable[str]`` of result URLs. This is the single seam the recon
loop depends on, so swapping how results are obtained never touches the
recon logic.

Two backends ship:

* ``scrape``  — the original behaviour: scrape Google via the ``google``
  library. Zero setup, but brittle (Google blocks scraping).
* ``api``     — the official Google Programmable Search / Custom Search JSON
  API. Reliable and sanctioned, but requires an API key and a Search-Engine
  ID (``cx``). Credentials are read from the environment and are NEVER logged.

Neither backend changes what the tool does to a *target* — both query
Google's index; the target host is never contacted here.
"""

from __future__ import annotations

import logging
import os
from typing import Callable, Iterable

log = logging.getLogger("quick_recon")

SearchFn = Callable[[str], Iterable[str]]

API_KEY_ENV = "GOOGLE_API_KEY"
CSE_ID_ENV = "GOOGLE_CSE_ID"


class BackendError(Exception):
    """Raised when a backend cannot be constructed or configured."""


def scrape_backend(pause: float = 2.0) -> SearchFn:
    """Return a SearchFn backed by the ``google`` scraping library.

    Imported lazily so --help/--dry-run/tests work without the optional dep.
    """
    try:
        from googlesearch import search as google_search
    except ImportError as exc:  # pragma: no cover - depends on optional dep
        raise BackendError(
            "the 'google' library is not installed. "
            "Install it with: pip install -r requirements.txt"
        ) from exc

    def search(query: str) -> Iterable[str]:
        return google_search(query, num=30, stop=60, pause=pause)

    return search


def api_backend(
    api_key: str,
    cse_id: str,
    *,
    max_results: int = 30,
    http_get=None,
) -> SearchFn:
    """Return a SearchFn backed by the Google Custom Search JSON API.

    ``http_get`` is injectable for testing; at runtime it defaults to
    ``requests.get`` (imported lazily). The API returns up to 10 results per
    page, so we paginate via the ``start`` parameter up to ``max_results``.
    The API key is used only as a request parameter and is never logged.
    """
    if not api_key or not cse_id:
        raise BackendError(
            f"the API backend needs both {API_KEY_ENV} and {CSE_ID_ENV} set."
        )

    if http_get is None:
        def http_get(url, params=None, timeout=10):  # pragma: no cover - thin
            import requests

            return requests.get(url, params=params, timeout=timeout)

    endpoint = "https://www.googleapis.com/customsearch/v1"

    def search(query: str) -> Iterable[str]:
        links: list[str] = []
        start = 1
        while len(links) < max_results and start <= 91:  # API caps start<=91
            params = {
                "key": api_key,
                "cx": cse_id,
                "q": query,
                "start": start,
                "num": min(10, max_results - len(links)),
            }
            resp = http_get(endpoint, params=params, timeout=10)
            status = getattr(resp, "status_code", 200)
            if status != 200:
                # Log the status but never the key/params.
                raise BackendError(
                    f"Custom Search API returned HTTP {status}"
                )
            data = resp.json()
            items = data.get("items", [])
            if not items:
                break
            links.extend(item["link"] for item in items if "link" in item)
            start += len(items)
        return links[:max_results]

    return search


def build_backend(
    name: str,
    *,
    pause: float = 2.0,
    max_results: int = 30,
    env: dict[str, str] | None = None,
) -> SearchFn:
    """Construct a backend by name. ``env`` defaults to ``os.environ``."""
    env = os.environ if env is None else env
    if name == "scrape":
        return scrape_backend(pause=pause)
    if name == "api":
        return api_backend(
            env.get(API_KEY_ENV, ""),
            env.get(CSE_ID_ENV, ""),
            max_results=max_results,
        )
    raise BackendError(f"unknown backend {name!r} (choose 'scrape' or 'api')")

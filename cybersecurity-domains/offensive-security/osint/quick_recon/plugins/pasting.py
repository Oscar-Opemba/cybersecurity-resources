#!/usr/bin/env python3
"""Paste-site recon plugin.

Superseded by the ``paste_sites`` check in ``recon_lib.CHECKS`` (which the
main tool runs automatically). This module is kept as a minimal, importable
example of a stand-alone plugin.

The original version executed at import time, wrote the target to a
world-readable ``quick_recon.config`` file and then ``os.remove()``'d it —
a race condition and information leak. That behaviour has been removed; the
plugin is now a pure function you pass a target and a search function to.
"""

from __future__ import annotations

import sys
from pathlib import Path
from typing import Iterable

# Allow running this file directly for a quick demo.
sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from recon_lib import Check, normalize_result  # noqa: E402

PASTE_CHECK = Check(
    "paste_sites",
    "Paste-site mentions",
    "site:pastebin.com | site:hastebin.com | site:carbon.now.sh {target}",
)


def find_paste_mentions(target: str, search) -> list[str]:
    """Return de-duplicated paste-site result URLs for ``target``.

    ``search`` is a callable ``query -> iterable[str]`` (inject the real
    googlesearch at runtime, or a fake in tests). No network here.
    """
    results: Iterable[str] = search(PASTE_CHECK.query(target))
    seen: set[str] = set()
    out: list[str] = []
    for url in results:
        norm = normalize_result(url)
        if norm not in seen:
            seen.add(norm)
            out.append(norm)
    return out

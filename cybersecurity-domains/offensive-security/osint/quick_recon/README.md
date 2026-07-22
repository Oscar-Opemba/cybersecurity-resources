# quick_recon

Safe-by-default OSINT **subdomain / dork recon** for a single **authorized**
target. Given a domain you are allowed to test, it runs a fixed set of Google
dork queries (subdomains, login/signup pages, directory listings, exposed
documents, WordPress paths, paste-site mentions) and produces a structured
report.

> ⚠️ **AUTHORIZED USE ONLY.** Run this only against domains you own or are
> explicitly authorized to assess. See [`LEGAL.md`](../../../../LEGAL.md) at
> the repository root. The tool refuses to run against a target that is not in
> your scope file.

Originally by [Adnane X Tebbaa](https://github.com/adnane-x-tebbaa/quick_recon);
hardened here for engagement use (scope enforcement, dry-run, rate limiting,
retries, structured logging, machine-readable reports, tests).

## What it actually does

It **scrapes Google** via the third-party `google` library. That mechanism is
inherently brittle — Google actively blocks scraping, so live runs may return
partial results or get rate-limited. The hardening in this repo makes runs
**safe and predictable**, not the scraping reliable. For a dependable pipeline
you would swap in a supported search API; that changes behaviour and is left as
a deliberate operator decision.

## Setup (≤5 commands)

```bash
cd cybersecurity-domains/offensive-security/osint/quick_recon
python3 -m venv .venv && source .venv/bin/activate
pip install -r requirements.txt
cp scope.example.txt scope.txt   # then edit scope.txt with YOUR authorized domains
```

## Usage

```bash
# Preview exactly what would run — no network activity at all:
python3 quick_recon.py example.com --scope-file scope.txt --dry-run

# Live run against an in-scope target, JSON report to a file:
python3 quick_recon.py example.com --scope-file scope.txt \
    --format json --output example.report.json

# If you genuinely cannot use a scope file, assert authorization explicitly:
python3 quick_recon.py example.com --i-am-authorized
```

Key flags:

| Flag | Meaning |
|------|---------|
| `--scope-file FILE` | Allow-list of authorized domains (required unless `--i-am-authorized`). |
| `--i-am-authorized` | Run without a scope file; you still confirm the target. |
| `--dry-run` | Print the exact queries and exit — **no network**. |
| `--yes` | Skip the interactive confirmation (automation). |
| `--pause N` | Seconds between Google requests (rate limit, default 2.0). |
| `--retries N` | Retries per check on transient failure (default 2). |
| `--format {text,json,csv}` | Report format. |
| `--output FILE` | Write the report to a file instead of stdout. |

### Exit codes

| Code | Meaning |
|------|---------|
| 0 | Completed (a clean "no findings" report is still success). |
| 1 | Aborted by operator (declined confirmation / interrupted). |
| 2 | Usage error (no target, no scope, bad input). |
| 3 | **Refused: target not in scope.** |
| 4 | Search backend failure. |

## Safety model

- **Scope enforcement** — a target must exactly match, or be a sub-domain of,
  an entry in your scope file. No wildcards, no implicit "all"; an empty scope
  allows nothing. Look-alikes (`notexample.com` vs `example.com`) are rejected.
- **Confirmation gate** — every run confirms the target before acting (skippable
  only via explicit `--yes`).
- **Dry-run** — review the full query plan with zero network activity.
- **Rate limiting** — a minimum interval between requests, on by default.
- **Graceful failure** — each check retries with backoff and records an error
  instead of crashing the run; `Ctrl-C` writes a partial report.
- **No secret leakage** — no target/config file is written to disk during a run
  (the old `quick_recon.config` write/delete race was removed). `scope.txt` and
  report outputs are git-ignored.

## Sample output (dry-run)

```
============================================================
quick_recon report for: example.com
scope:      example.com
dry-run:    True
findings:   0
============================================================
```

## Development

```bash
pip install -r requirements-dev.txt
python3 -m pytest -q      # 42 tests, all network mocked — no live calls
ruff check .              # lint
```

The code is split so logic is testable without a network:

- `safety.py` — scope, rate limiting, confirmation (pure/local).
- `recon_lib.py` — the checks (as data) and the run loop; search is injected.
- `report.py` — the result model (text / JSON / CSV).
- `quick_recon.py` — the CLI wiring it together.
- `plugins/pasting.py` — example stand-alone plugin.

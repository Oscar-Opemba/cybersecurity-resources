# quick_scanner

Safe-by-default **TCP connect port scanner** for a single **authorized** host.
Given an IP or hostname you are allowed to test, it probes a set of TCP ports
and reports which are open, as text / JSON / CSV.

> ⚠️ **AUTHORIZED USE ONLY.** A port scan *contacts the target host*. Run this
> only against systems you own or are explicitly authorized to test. See
> [`LEGAL.md`](../../../../../LEGAL.md) at the repository root. The scanner
> refuses to run against a target that is not in your scope file.

Originally a teaching demo by Omar Santos (@santosomar); hardened here for
engagement use (scope enforcement, dry-run, confirmation, bounded concurrency
with rate limiting, graceful failure, structured reports, tests).

## Setup (≤3 commands)

```bash
cd cybersecurity-domains/application-security/programming-and-scripting-for-cybersecurity/recon_scripts/scanning
printf '10.0.0.0/24\n' > scan_scope.txt   # your authorized IPs/CIDRs/hostnames
python3 quick_scanner.py --help
```

No runtime dependencies — standard library only.

## Usage

```bash
# Preview the scan plan — no resolution, no connections:
python3 quick_scanner.py 10.0.0.5 --ports 1-1024 --scope-file scan_scope.txt --dry-run

# Live scan of an in-scope host, JSON report to a file:
python3 quick_scanner.py 10.0.0.5 --ports 22,80,443 --scope-file scan_scope.txt \
    --format json --output host.report.json

# Reproduce the original sequential behaviour exactly:
python3 quick_scanner.py 10.0.0.5 --concurrency 1 --scope-file scan_scope.txt
```

Key flags:

| Flag | Meaning |
|------|---------|
| `--ports SPEC` | `1-1024`, `22,80,443`, or `22-25,443`. Default `1-1024`. |
| `--scope-file FILE` | Allow-list of IPs/CIDRs/hostnames (required unless `--i-am-authorized`). |
| `--i-am-authorized` | Scan without a scope file; target still confirmed. |
| `--dry-run` | Show the plan and exit — **no network**. |
| `--yes` | Skip the confirmation prompt (automation). |
| `--concurrency N` | Parallel workers, 1–256. `1` = sequential. Default 16. |
| `--rate N` | Max connections/sec across all workers (0 = unbounded by rate). |
| `--timeout N` | Per-connection timeout, seconds. Default 1.0. |
| `--format {text,json,csv}` / `--output FILE` | Report format / destination. |

### Exit codes

| Code | Meaning |
|------|---------|
| 0 | Completed (no open ports is still success). |
| 1 | Aborted by operator. |
| 2 | Usage error (no target, bad ports, no scope). |
| 3 | **Refused: target not in scope.** |

## Safety model

- **Scope enforcement (IP/CIDR/hostname)** — an IP target must fall inside an
  allowed network; a hostname target must be an *exact* scope entry.
  **Hostnames are never resolved for the scope check**, so a DNS answer can't
  be used to sneak a target into scope. Out-of-scope → exit 3.
- **Confirmation gate** before any scan (skippable only via `--yes`).
- **Dry-run** — full plan with zero network activity.
- **Bounded concurrency** — parallelism is clamped to a hard max of 256 so a
  fat-fingered `--concurrency` can't turn this into a DoS. Optional `--rate`
  caps connections/second across all workers.
- **Graceful failure** — an unresolvable host is reported (not a traceback);
  a single failing port is isolated and the scan continues; `Ctrl-C` writes a
  partial report.

### A note on operational behaviour vs. the original

The original scanned **sequentially**. This version defaults to **16 parallel
workers** for usable speed — more parallel than the original, but hard-capped
and rate-limitable. Pass `--concurrency 1` to reproduce the original exactly.
This is the only behavioural change; the capability (a TCP connect scan of a
port range on one host) is unchanged.

## Development

```bash
pip install -r requirements-dev.txt
python3 -m pytest -q      # 32 tests, connect/resolver mocked — no live scan
ruff check quick_scanner.py scanner_lib.py tests/
```

- `scanner_lib.py` — target/port parsing, scope, rate limiter, scan loop,
  report model. Network is injected (`connect` / `resolver`).
- `quick_scanner.py` — the CLI.

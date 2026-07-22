# basic_ping_sweep

Safe-by-default **ICMP host-discovery sweep** for an **authorized** range.
Given a CIDR, single IP, or dashed range you are allowed to test, it pings
each host and reports which are up, as text / JSON / CSV.

> ⚠️ **AUTHORIZED USE ONLY.** A sweep contacts *many* hosts. Run it only
> against ranges you own or are explicitly authorized to test. See
> [`LEGAL.md`](../../../../../LEGAL.md) at the repository root. **Every** host
> in the expanded range must be in your scope file or the sweep is refused.

Originally a teaching demo with a **hardcoded `10.6.6.0/24`** target and no
scope check. Hardened here (scope, dry-run, confirmation, bounded concurrency,
rate limiting, size guard, structured reports, tests). It reuses the safety
primitives in `scanner_lib.py` (`Scope`, `RateLimiter`).

## Setup (≤3 commands)

```bash
cd cybersecurity-domains/application-security/programming-and-scripting-for-cybersecurity/recon_scripts/scanning
printf '10.6.6.0/24\n' > scan_scope.txt   # your authorized IPs/CIDRs
python3 basic_ping_sweep.py --help
```

No runtime dependencies — standard library + the system `ping`.

## Usage

```bash
# Preview the plan — no packets sent:
python3 basic_ping_sweep.py 10.6.6.0/24 --scope-file scan_scope.txt --dry-run

# Live sweep of an in-scope range, JSON report to a file:
python3 basic_ping_sweep.py 10.6.6.0/24 --scope-file scan_scope.txt \
    --format json --output sweep.report.json

# A dashed range, sequential (original behaviour):
python3 basic_ping_sweep.py 10.6.6.1-10.6.6.50 --scope-file scan_scope.txt --concurrency 1
```

Key flags:

| Flag | Meaning |
|------|---------|
| `target` | `10.6.6.0/24`, `10.6.6.5`, or `10.6.6.1-10.6.6.20`. |
| `--scope-file FILE` | Allow-list of IPs/CIDRs (required unless `--i-am-authorized`). |
| `--i-am-authorized` | Sweep without a scope file; still confirmed. |
| `--dry-run` | Show the plan and exit — **no packets**. |
| `--yes` | Skip the confirmation prompt (automation). |
| `--concurrency N` | Parallel ping workers, 1–256. `1` = sequential. Default 32. |
| `--rate N` | Max pings/sec across all workers (0 = unbounded by rate). |
| `--timeout N` | Per-ping timeout, seconds. Default 1.0. |
| `--format {text,json,csv}` / `--output FILE` | Report format / destination. |

### Exit codes

| Code | Meaning |
|------|---------|
| 0 | Completed (no hosts up is still success). |
| 1 | Aborted by operator. |
| 2 | Usage error (no/invalid target, oversized range, no scope). |
| 3 | **Refused: one or more hosts not in scope.** |

## Safety model

- **Whole-range scope gate** — the range is expanded first, then **every**
  host is checked against the scope file. If *any* host is out of scope the
  **entire sweep is refused** (exit 3). This is stricter than single-host
  scope: you can't smuggle an out-of-scope host inside an in-scope-looking
  CIDR.
- **Size guard** — a range expanding to more than 65,536 hosts (a /16) is
  refused, so a fat-fingered prefix can't launch a massive sweep.
- **Confirmation gate** showing the host count before sending anything.
- **Dry-run** — full plan with zero packets.
- **Bounded concurrency** — clamped to a hard max of 256; optional `--rate`
  caps pings/second.
- **Graceful failure** — a host that errors is isolated and the sweep
  continues; `Ctrl-C` writes a partial report.

### Behavioural note

The original hardcoded `10.6.6.0/24` and swept **sequentially**. This version
takes the range as an argument and defaults to **32 parallel workers** (capped
and rate-limitable); `--concurrency 1` reproduces the sequential behaviour. The
capability (ICMP echo host discovery over a range) is unchanged.

## Development

```bash
pip install -r requirements-dev.txt
python3 -m pytest -q      # pinger mocked — no packets sent
ruff check basic_ping_sweep.py sweep_lib.py
```

- `sweep_lib.py` — range expansion, size guard, whole-range scope gate, sweep
  loop, report model. The pinger is injected.
- `basic_ping_sweep.py` — the CLI.

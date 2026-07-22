# python_nmap

Safe-by-default wrapper around the **`python-nmap`** library (which drives the
system `nmap`) for an **authorized** target range. Runs a basic port scan and
produces a structured report (text / JSON / CSV).

> ⚠️ **AUTHORIZED USE ONLY.** An nmap scan contacts the target host(s). Run it
> only against systems you own or are explicitly authorized to test. See
> [`LEGAL.md`](../../../../../LEGAL.md). Every host in the expanded range must
> be in your scope file or the scan is refused.

Originally a teaching demo by Omar Santos (@santosomar). The original **crashed
on Python 3** (`print(...) % (host)` raises `TypeError`) and had no scope check.
Fixed and hardened here (scope gate, dry-run, confirmation, structured output,
injectable/testable scan function).

## Setup

```bash
pip install python-nmap          # and ensure the 'nmap' binary is on PATH
printf '10.0.0.0/24\n' > scan_scope.txt
python3 python_nmap.py --help
```

## Usage

```bash
# Preview — nmap is not invoked:
python3 python_nmap.py 10.0.0.5 --ports 22,80,443 --scope-file scan_scope.txt --dry-run

# Live scan of an in-scope host, JSON report:
python3 python_nmap.py 10.0.0.5 --ports 1-1024 --scope-file scan_scope.txt \
    --format json --output host.report.json
```

| Flag | Meaning |
|------|---------|
| `target` | CIDR, single IP, or dashed range. |
| `--ports SPEC` | `1-1024`, `22,80,443`. Default `1-1024`. |
| `--scope-file FILE` | Allow-list of IPs/CIDRs (required unless `--i-am-authorized`). |
| `--i-am-authorized` | Scan without a scope file; still confirmed. |
| `--dry-run` | Show the plan and exit — nmap not invoked. |
| `--yes` | Skip the confirmation prompt. |
| `--format {text,json,csv}` / `--output FILE` | Report format / destination. |

### Exit codes

| Code | Meaning |
|------|---------|
| 0 | Completed. |
| 1 | Aborted by operator. |
| 2 | Usage error (no/invalid target or ports, no scope). |
| 3 | **Refused: one or more hosts not in scope.** |
| 4 | nmap backend unavailable / scan failed. |

## Safety model & scope

Same whole-range scope gate as `basic_ping_sweep`: the target is expanded and
**every** host must be in scope, or the entire scan is refused. Confirmation
and dry-run apply before nmap is ever invoked.

**Capability is unchanged:** this runs a *basic* nmap port scan. It
deliberately does **not** expose nmap's aggressive options (no custom
`-sS`/`-A`/NSE arguments) — this pass hardens the existing capability, it does
not expand it.

## Development

```bash
python3 -m pytest -q     # scan function mocked — nmap never runs
ruff check python_nmap.py nmap_lib.py
```

- `nmap_lib.py` — injectable scan function + report model.
- `python_nmap.py` — the CLI (scope gate, dry-run, confirmation).

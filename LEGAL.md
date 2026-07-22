# Legal & Authorized-Use Notice

This repository is a collection of cybersecurity **references, training
material, and example scripts**. Several scripts can interact with networks and
hosts (port scanners, ping sweeps, OSINT recon, packet tooling, exploit
demonstrations).

## Authorized use only

You may use the offensive/testing tooling in this repository **only** against
systems that you own or for which you have **explicit, written authorization**
to test — for example:

- your own lab or hardware,
- an intentionally vulnerable practice target (DVWA, Metasploitable, the
  WebSploit lab, a CTF you are entered in), or
- an engagement covered by a signed contract / rules of engagement, within the
  agreed scope.

Running these tools against systems you are not authorized to test may be
**illegal** (e.g. the U.S. Computer Fraud and Abuse Act, the UK Computer Misuse
Act, and equivalent laws worldwide) and is not endorsed here.

## No warranty

All material is provided "as is", for **educational and authorized security
research purposes**, without warranty of any kind. The authors and contributors
accept **no liability** for misuse or for any damage arising from use of this
material. See [`LICENSE`](LICENSE).

## Scope safety

Many scripts in this repository are deliberately minimal teaching examples and
do **not** enforce scope on their own — they will act on whatever target you
give them. Treat every target string as load-bearing:

- Prefer tools that support a scope allow-list and a dry-run mode (e.g.
  `cybersecurity-domains/offensive-security/osint/quick_recon`).
- Double-check target IPs/domains before running anything.
- Watch for hardcoded targets in example scripts (e.g. the `10.6.6.0/24`
  WebSploit lab range in `basic_ping_sweep.py`) and change them for your own
  authorized lab.

## Reporting

If you find a security issue in the tooling itself, please open an issue rather
than filing it against an unrelated third party.

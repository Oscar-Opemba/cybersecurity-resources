#!/usr/bin/env python3
"""scapscan — safe-by-default scapy multi-technique port scanner.

Hardened from the original teaching demo. Two important changes:

1. Correctness: the original checked ``str(type(resp)) == "<type 'NoneType'>"``,
   which is the Python 2 repr — on Python 3 it is ``<class 'NoneType'>``, so
   timeout (None) responses were never detected and the next line crashed with
   ``AttributeError``. Now uses ``resp is None``.
2. Safety: scope enforcement, confirmation and a dry-run gate run BEFORE any
   packet is crafted or sent.

Supports the same techniques as before (TCP-connect, stealth/SYN, XMAS, FIN,
NULL, ACK, window, UDP) — no techniques added or removed. Sends raw packets
and needs root. Authorized use only. See LEGAL.md at the repository root.

NOTE: the raw-packet scan functions are not unit-tested — they require root
and a live network to exercise meaningfully, and mocking scapy's packet layers
would only test the mock. The scope/confirmation/dry-run gate (which is the
security-relevant part) is what protects against firing at an unintended host.
"""
from __future__ import annotations

import argparse
import logging
import sys

from scanner_lib import Scope, ScopeError, normalize_target
from sweep_lib import check_all_in_scope

logging.getLogger("scapy.runtime").setLevel(logging.ERROR)  # suppress warnings
log = logging.getLogger("scapscan")

_SCAPY = None


def _scapy():
    """Import and cache scapy.all lazily (so --help/--dry-run need no scapy)."""
    global _SCAPY
    if _SCAPY is None:
        from scapy.all import conf  # noqa: F401
        import scapy.all as scapy_all

        scapy_all.conf.verb = 0
        _SCAPY = scapy_all
    return _SCAPY


def tcp_connect_scan(dst_ip, dst_port, dst_timeout):
    s = _scapy()
    src_port = s.RandShort()
    resp = s.sr1(s.IP(dst=dst_ip) / s.TCP(sport=src_port, dport=dst_port,
                                          flags="S"), timeout=dst_timeout)
    if resp is None:
        return "Closed"
    if resp.haslayer(s.TCP):
        if resp.getlayer(s.TCP).flags == 0x12:
            s.sr(s.IP(dst=dst_ip) / s.TCP(sport=src_port, dport=dst_port,
                                          flags="AR"), timeout=dst_timeout)
            return "Open"
        if resp.getlayer(s.TCP).flags == 0x14:
            return "Closed"
    return "CHECK"


def stealth_scan(dst_ip, dst_port, dst_timeout):
    s = _scapy()
    src_port = s.RandShort()
    resp = s.sr1(s.IP(dst=dst_ip) / s.TCP(sport=src_port, dport=dst_port,
                                          flags="S"), timeout=dst_timeout)
    if resp is None:
        return "Filtered"
    if resp.haslayer(s.TCP):
        if resp.getlayer(s.TCP).flags == 0x12:
            s.sr(s.IP(dst=dst_ip) / s.TCP(sport=src_port, dport=dst_port,
                                          flags="R"), timeout=dst_timeout)
            return "Open"
        if resp.getlayer(s.TCP).flags == 0x14:
            return "Closed"
    if resp.haslayer(s.ICMP):
        icmp = resp.getlayer(s.ICMP)
        if int(icmp.type) == 3 and int(icmp.code) in [1, 2, 3, 9, 10, 13]:
            return "Filtered"
    return "CHECK"


def xmas_scan(dst_ip, dst_port, dst_timeout):
    s = _scapy()
    resp = s.sr1(s.IP(dst=dst_ip) / s.TCP(dport=dst_port, flags="FPU"),
                 timeout=dst_timeout)
    if resp is None:
        return "Open|Filtered"
    if resp.haslayer(s.TCP):
        if resp.getlayer(s.TCP).flags == 0x14:
            return "Closed"
    if resp.haslayer(s.ICMP):
        icmp = resp.getlayer(s.ICMP)
        if int(icmp.type) == 3 and int(icmp.code) in [1, 2, 3, 9, 10, 13]:
            return "Filtered"
    return "CHECK"


def fin_scan(dst_ip, dst_port, dst_timeout):
    s = _scapy()
    resp = s.sr1(s.IP(dst=dst_ip) / s.TCP(dport=dst_port, flags="F"),
                 timeout=dst_timeout)
    if resp is None:
        return "Open|Filtered"
    if resp.haslayer(s.TCP):
        if resp.getlayer(s.TCP).flags == 0x14:
            return "Closed"
    if resp.haslayer(s.ICMP):
        icmp = resp.getlayer(s.ICMP)
        if int(icmp.type) == 3 and int(icmp.code) in [1, 2, 3, 9, 10, 13]:
            return "Filtered"
    return "CHECK"


def null_scan(dst_ip, dst_port, dst_timeout):
    s = _scapy()
    resp = s.sr1(s.IP(dst=dst_ip) / s.TCP(dport=dst_port, flags=""),
                 timeout=dst_timeout)
    if resp is None:
        return "Open|Filtered"
    if resp.haslayer(s.TCP):
        if resp.getlayer(s.TCP).flags == 0x14:
            return "Closed"
    if resp.haslayer(s.ICMP):
        icmp = resp.getlayer(s.ICMP)
        if int(icmp.type) == 3 and int(icmp.code) in [1, 2, 3, 9, 10, 13]:
            return "Filtered"
    return "CHECK"


def ack_flag_scan(dst_ip, dst_port, dst_timeout):
    s = _scapy()
    resp = s.sr1(s.IP(dst=dst_ip) / s.TCP(dport=dst_port, flags="A"),
                 timeout=dst_timeout)
    if resp is None:
        return "Stateful firewall present\n(Filtered)"
    if resp.haslayer(s.TCP):
        if resp.getlayer(s.TCP).flags == 0x4:
            return "No firewall\n(Unfiltered)"
    if resp.haslayer(s.ICMP):
        icmp = resp.getlayer(s.ICMP)
        if int(icmp.type) == 3 and int(icmp.code) in [1, 2, 3, 9, 10, 13]:
            return "Stateful firewall present\n(Filtered)"
    return "CHECK"


def window_scan(dst_ip, dst_port, dst_timeout):
    s = _scapy()
    resp = s.sr1(s.IP(dst=dst_ip) / s.TCP(dport=dst_port, flags="A"),
                 timeout=dst_timeout)
    if resp is None:
        return "No response"
    if resp.haslayer(s.TCP):
        if resp.getlayer(s.TCP).window == 0:
            return "Closed"
        if resp.getlayer(s.TCP).window > 0:
            return "Open"
    return "CHECK"


def udp_scan(dst_ip, dst_port, dst_timeout):
    s = _scapy()
    resp = s.sr1(s.IP(dst=dst_ip) / s.UDP(dport=dst_port), timeout=dst_timeout)
    if resp is None:
        for _count in range(0, 3):
            retry = s.sr1(s.IP(dst=dst_ip) / s.UDP(dport=dst_port),
                          timeout=dst_timeout)
            if retry is not None:
                return udp_scan(dst_ip, dst_port, dst_timeout)
        return "Open|Filtered"
    if resp.haslayer(s.UDP):
        return "Open"
    if resp.haslayer(s.ICMP):
        icmp = resp.getlayer(s.ICMP)
        if int(icmp.type) == 3 and int(icmp.code) == 3:
            return "Closed"
        if int(icmp.type) == 3 and int(icmp.code) in [1, 2, 9, 10, 13]:
            return "Filtered"
    return "CHECK"


def start(target, ports, timeout):
    import prettytable

    table = prettytable.PrettyTable(
        ["Port No.", "TCP Connect", "Stealth", "XMAS", "FIN", "NULL",
         "ACK Flag", "Window", "UDP"]
    )
    table.align["Port No."] = "l"
    print(f"[+] Target : {target}\n")
    print("[*] Scan started\n")
    for port in ports:
        table.add_row([
            port,
            tcp_connect_scan(target, int(port), int(timeout)),
            stealth_scan(target, int(port), int(timeout)),
            xmas_scan(target, int(port), int(timeout)),
            fin_scan(target, int(port), int(timeout)),
            null_scan(target, int(port), int(timeout)),
            ack_flag_scan(target, int(port), int(timeout)),
            window_scan(target, int(port), int(timeout)),
            udp_scan(target, int(port), int(timeout)),
        ])
    print(table)
    print("\n[*] Scan completed\n")


def _parse_ports(args) -> list[int]:
    ports: set[int] = set()
    if args.p:
        ports.add(int(args.p))
    if args.pl:
        ports.update(int(x) for x in args.pl.split(","))
    if args.pr:
        lo_s, hi_s = args.pr.split("-")
        lo, hi = sorted((int(lo_s), int(hi_s)))
        ports.update(range(lo, hi + 1))
    return sorted(ports)


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="scapscan",
        description="Safe-by-default scapy multi-technique scanner "
        "(authorized use only). See LEGAL.md.",
    )
    parser.add_argument("target", help="Target IP address.")
    parser.add_argument("-p", metavar="", help="Single port e.g. 80")
    parser.add_argument("-pl", metavar="", help="Port list e.g. 21,22,80")
    parser.add_argument("-pr", metavar="", help="Port range e.g. 20-30")
    parser.add_argument("-t", metavar="", type=int, default=2,
                        help="Timeout value (default 2)")
    parser.add_argument("--scope-file",
                        help="Allow-list of authorized IPs/CIDRs.")
    parser.add_argument("--i-am-authorized", action="store_true",
                        help="Assert authorization without a scope file.")
    parser.add_argument("--dry-run", action="store_true",
                        help="Show the plan and exit — no packets sent.")
    parser.add_argument("--yes", action="store_true",
                        help="Skip the confirmation prompt.")
    return parser


def _resolve_scope(args):
    if args.scope_file:
        return Scope.from_file(args.scope_file)
    if args.i_am_authorized:
        return None
    raise ScopeError(
        "no scope provided. Pass --scope-file <file> or --i-am-authorized."
    )


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    logging.basicConfig(level=logging.INFO,
                        format="%(asctime)s %(levelname)s %(message)s")

    try:
        target = normalize_target(args.target)
    except ValueError as exc:
        log.error("Invalid target: %s", exc)
        return 2

    ports = _parse_ports(args)
    if not ports:
        log.error("No ports specified. Use -p, -pl or -pr (see --help).")
        return 2

    # --- Scope enforcement (safety rail) ---------------------------------
    try:
        scope = _resolve_scope(args)
    except ScopeError as exc:
        log.error("Scope error: %s", exc)
        return 2
    if scope is not None:
        try:
            check_all_in_scope([target], scope)
        except ScopeError as exc:
            log.error("Refusing to scan: %s", exc)
            return 3
    else:
        log.warning("Scanning without a scope file against %s", target)

    # --- Confirmation gate (safety rail) ---------------------------------
    action = "PREVIEW (dry-run)" if args.dry_run else "raw-packet scan"
    if not args.yes:
        answer = input(
            f"About to {action} {target} on {len(ports)} port(s). "
            "Authorized? [y/N]: "
        ).strip().lower()
        if answer not in {"y", "yes"}:
            log.error("Aborted by operator.")
            return 1

    if args.dry_run:
        print(f"dry-run: would scan {target} on ports "
              f"{','.join(str(p) for p in ports)} "
              "using TCP-connect/stealth/XMAS/FIN/NULL/ACK/window/UDP.")
        return 0

    start(target, ports, args.t)
    return 0


if __name__ == "__main__":
    sys.exit(main())

#!/usr/bin/env python3
"""simple_scapy_scan — safe-by-default ARP / TCP-SYN scanner (scapy).

Hardened from the original teaching demo: explicit scope enforcement,
confirmation, and dry-run gate BEFORE any packet is sent. The packet senders
are injected and return plain tuples, so the result-parsing logic is
unit-testable without scapy, root, or a live network.

Sends raw ARP / TCP-SYN packets and needs root. Run it only against hosts you
own or are explicitly authorized to test. See LEGAL.md at the repo root.
"""

from __future__ import annotations

import argparse
import logging
import sys

from scanner_lib import Scope, ScopeError, normalize_target
from sweep_lib import SweepError, check_all_in_scope, expand_targets

log = logging.getLogger("simple_scapy_scan")


# --------------------------------------------------------------------------- #
# Scanning. Senders are injected and return plain tuples, keeping all scapy
# specifics behind the default factories and the parsing logic testable.
# --------------------------------------------------------------------------- #
def _default_srp():
    """Return an srp_fn(ip) -> list of (psrc, hwsrc) tuples."""
    from scapy.all import ARP, Ether, srp

    def srp_fn(ip):
        request = Ether(dst="ff:ff:ff:ff:ff:ff") / ARP(pdst=ip)
        ans, _ = srp(request, timeout=2, retry=1, verbose=0)
        return [(rcv.psrc, rcv.hwsrc) for _snt, rcv in ans]

    return srp_fn


def _default_sr():
    """Return an sr_fn(ip, ports) -> list of (flags, sport) tuples."""
    from scapy.all import IP, TCP, sr

    def sr_fn(ip, ports):
        syn = IP(dst=ip) / TCP(dport=ports, flags="S")
        ans, _ = sr(syn, timeout=2, retry=1, verbose=0)
        out = []
        for _snt, rcv in ans:
            if rcv.haslayer(TCP):
                tcp = rcv[TCP]
                out.append((str(tcp.flags), int(tcp.sport)))
        return out

    return sr_fn


def arp_scan(ip, srp_fn=None):
    """ARP-scan an IP/range. Returns list of {'IP':.., 'MAC':..} dicts."""
    if srp_fn is None:
        srp_fn = _default_srp()
    return [{"IP": psrc, "MAC": hwsrc} for psrc, hwsrc in srp_fn(ip)]


def tcp_scan(ip, ports, sr_fn=None):
    """TCP-SYN scan. Returns the sorted list of open ports (SYN/ACK replies)."""
    if sr_fn is None:
        sr_fn = _default_sr()
    open_ports = [sport for flags, sport in sr_fn(ip, ports) if flags == "SA"]
    return sorted(set(open_ports))


# --------------------------------------------------------------------------- #
# CLI
# --------------------------------------------------------------------------- #
def _add_scope_args(sub):
    sub.add_argument("--scope-file", help="Allow-list of IPs/CIDRs.")
    sub.add_argument("--i-am-authorized", action="store_true",
                     help="Assert authorization without a scope file.")
    sub.add_argument("--dry-run", action="store_true",
                     help="Show the plan and exit — no packets sent.")
    sub.add_argument("--yes", action="store_true",
                     help="Skip the confirmation prompt.")


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="simple_scapy_scan",
        description="Safe-by-default ARP/TCP-SYN scanner (authorized use only).",
        epilog="Authorized use only. See LEGAL.md.",
    )
    subparsers = parser.add_subparsers(
        dest="command", help="Command to perform.", required=True
    )

    arp = subparsers.add_parser("ARP", help="Network scan using ARP requests.")
    arp.add_argument("IP", help="IP (192.168.88.1) or range (192.168.88.0/24).")
    _add_scope_args(arp)

    tcp = subparsers.add_parser("TCP", help="TCP scan using SYN packets.")
    tcp.add_argument("IP", help="An IP address to target.")
    tcp.add_argument("ports", nargs="+", type=int,
                     help="Ports to scan (space-delimited), or low high with "
                     "--range.")
    tcp.add_argument("--range", action="store_true",
                     help="Treat <ports> as an inclusive <low> <high> range.")
    _add_scope_args(tcp)
    return parser


def _resolve_scope(args):
    if args.scope_file:
        return Scope.from_file(args.scope_file)
    if args.i_am_authorized:
        return None
    raise ScopeError(
        "no scope provided. Pass --scope-file <file> or --i-am-authorized."
    )


def _gate(args, hosts: list[str]) -> int | None:
    """Enforce scope + confirmation. Returns an exit code to stop, or None."""
    try:
        scope = _resolve_scope(args)
    except ScopeError as exc:
        log.error("Scope error: %s", exc)
        return 2
    if scope is not None:
        try:
            check_all_in_scope(hosts, scope)
        except ScopeError as exc:
            log.error("Refusing to scan: %s", exc)
            return 3
    else:
        log.warning("Scanning without a scope file (%d host(s))", len(hosts))

    action = "PREVIEW (dry-run)" if args.dry_run else "scan"
    if not args.yes:
        answer = input(
            f"About to {action} {len(hosts)} host(s). Authorized? [y/N]: "
        ).strip().lower()
        if answer not in {"y", "yes"}:
            log.error("Aborted by operator.")
            return 1
    return None


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    logging.basicConfig(level=logging.INFO,
                        format="%(asctime)s %(levelname)s %(message)s")

    if args.command == "ARP":
        try:
            hosts = expand_targets(args.IP)
        except SweepError as exc:
            log.error("Invalid target: %s", exc)
            return 2
        rc = _gate(args, hosts)
        if rc is not None:
            return rc
        if args.dry_run:
            print(f"dry-run: would ARP-scan {len(hosts)} host(s) "
                  f"({hosts[0]} … {hosts[-1]})")
            return 0
        for mapping in arp_scan(args.IP):
            print(f"{mapping['IP']} ==> {mapping['MAC']}")
        return 0

    # TCP
    try:
        target = normalize_target(args.IP)
    except ValueError as exc:
        log.error("Invalid target: %s", exc)
        return 2
    rc = _gate(args, [target])
    if rc is not None:
        return rc
    ports = tuple(args.ports) if args.range else args.ports
    if args.dry_run:
        print(f"dry-run: would TCP-SYN scan {target} ports {ports}")
        return 0
    for port in tcp_scan(target, ports):
        print(f"Port {port} is open.")
    return 0


if __name__ == "__main__":
    sys.exit(main())

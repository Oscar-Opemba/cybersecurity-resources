"""Tests for the scapy scanners. Packet senders are injected / gated —
no scapy, no root, no packets."""

import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

import scapscan
import simple_scapy_scan as sss


# --- simple_scapy_scan: parsing logic with injected senders -------------- #
def test_arp_scan_parses_injected_results():
    def fake_srp(ip):
        return [("10.0.0.1", "aa:bb:cc:00:11:22"),
                ("10.0.0.9", "aa:bb:cc:33:44:55")]
    result = sss.arp_scan("10.0.0.0/24", srp_fn=fake_srp)
    assert result == [
        {"IP": "10.0.0.1", "MAC": "aa:bb:cc:00:11:22"},
        {"IP": "10.0.0.9", "MAC": "aa:bb:cc:33:44:55"},
    ]


def test_tcp_scan_returns_only_syn_ack_ports_sorted():
    # (flags, sport) pairs: only "SA" (SYN/ACK) means open.
    def fake_sr(ip, ports):
        return [("SA", 80), ("RA", 22), ("SA", 443), ("SA", 80)]
    assert sss.tcp_scan("10.0.0.5", [22, 80, 443], sr_fn=fake_sr) == [80, 443]


def test_tcp_scan_no_open_ports():
    def fake_sr(ip, ports):
        return [("RA", 22), ("RA", 80)]
    assert sss.tcp_scan("10.0.0.5", [22, 80], sr_fn=fake_sr) == []


# --- simple_scapy_scan: CLI scope gate ----------------------------------- #
@pytest.fixture
def scope_file(tmp_path):
    f = tmp_path / "scope.txt"
    f.write_text("10.0.0.0/24\n")
    return str(f)


def test_sss_arp_out_of_scope_refused(scope_file, caplog):
    rc = sss.main(["ARP", "10.9.9.0/28", "--scope-file", scope_file, "--yes"])
    assert rc == 3


def test_sss_arp_dry_run_no_packets(scope_file, capsys):
    rc = sss.main(["ARP", "10.0.0.0/28", "--scope-file", scope_file,
                   "--yes", "--dry-run"])
    assert rc == 0
    assert "dry-run:" in capsys.readouterr().out


def test_sss_tcp_no_scope_refused(caplog):
    rc = sss.main(["TCP", "10.0.0.5", "80", "--yes"])
    assert rc == 2
    assert "no scope provided" in caplog.text


def test_sss_tcp_dry_run_no_packets(scope_file, capsys):
    rc = sss.main(["TCP", "10.0.0.5", "22", "80", "--scope-file", scope_file,
                   "--yes", "--dry-run"])
    assert rc == 0
    assert "dry-run:" in capsys.readouterr().out


# --- scapscan: CLI scope gate (raw-packet scans not unit-tested) --------- #
def test_scapscan_out_of_scope_refused(scope_file, caplog):
    rc = scapscan.main(["10.9.9.9", "-p", "80", "--scope-file", scope_file,
                        "--yes"])
    assert rc == 3


def test_scapscan_no_ports_returns_2(scope_file):
    rc = scapscan.main(["10.0.0.5", "--scope-file", scope_file, "--yes"])
    assert rc == 2


def test_scapscan_dry_run_no_packets(scope_file, capsys):
    rc = scapscan.main(["10.0.0.5", "-pl", "22,80,443", "--scope-file",
                        scope_file, "--yes", "--dry-run"])
    assert rc == 0
    assert "dry-run:" in capsys.readouterr().out


def test_scapscan_port_parsing():
    parser = scapscan.build_parser()
    args = parser.parse_args(["10.0.0.5", "-pr", "20-23"])
    assert scapscan._parse_ports(args) == [20, 21, 22, 23]
    args = parser.parse_args(["10.0.0.5", "-pl", "443,22,443"])
    assert scapscan._parse_ports(args) == [22, 443]

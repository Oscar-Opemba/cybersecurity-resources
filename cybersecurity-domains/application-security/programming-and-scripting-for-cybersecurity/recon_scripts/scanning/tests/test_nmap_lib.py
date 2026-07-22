"""Unit tests for nmap_lib. The scan function is faked — nmap never runs."""

import json
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from nmap_lib import NmapError, NmapReport, run_nmap


def fake_scan(mapping):
    """Return a ScanFn yielding the given host->[(port,state)] mapping."""
    return lambda hosts, ports: mapping


def test_run_nmap_populates_results():
    report = NmapReport(target="10.0.0.5")
    run_nmap(
        ["10.0.0.5"], "22,80", report,
        scan_fn=fake_scan({"10.0.0.5": [(22, "open"), (80, "closed")]}),
    )
    assert report.hosts_total == 1
    assert report.results["10.0.0.5"] == [
        {"port": 22, "state": "open"},
        {"port": 80, "state": "closed"},
    ]
    assert report.open_count() == 1


def test_run_nmap_dry_run_does_not_scan():
    tripped = {"n": 0}

    def scan_fn(hosts, ports):
        tripped["n"] += 1
        return {}

    report = NmapReport(target="10.0.0.0/29", dry_run=True)
    run_nmap(
        ["10.0.0.1", "10.0.0.2"], "1-1024", report,
        scan_fn=scan_fn, dry_run=True,
    )
    assert tripped["n"] == 0
    assert report.hosts_total == 2
    assert any(e.startswith("dry-run:") for e in report.errors)


def test_run_nmap_backend_error_recorded():
    def broken(hosts, ports):
        raise NmapError("nmap not installed")

    report = NmapReport(target="10.0.0.5")
    run_nmap(["10.0.0.5"], "22", report, scan_fn=broken)
    assert report.results == {}
    assert any("nmap not installed" in e for e in report.errors)


def test_report_json_and_csv():
    report = NmapReport(target="10.0.0.5")
    run_nmap(
        ["10.0.0.5"], "22,443", report,
        scan_fn=fake_scan({"10.0.0.5": [(22, "open"), (443, "open")]}),
    )
    data = json.loads(report.to_json())
    assert data["results"]["10.0.0.5"][0]["port"] == 22
    csv_lines = report.to_csv().strip().splitlines()
    assert csv_lines[0] == "host,port,state"
    assert len(csv_lines) == 3   # header + 2 ports


def test_report_text_clean_result():
    report = NmapReport(target="10.0.0.5")
    run_nmap(["10.0.0.5"], "22", report, scan_fn=fake_scan({}))
    assert "No results" in report.to_text()

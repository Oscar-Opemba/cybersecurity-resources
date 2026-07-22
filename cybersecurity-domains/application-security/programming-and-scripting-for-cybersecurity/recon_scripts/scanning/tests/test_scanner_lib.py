"""Unit tests for scanner_lib. Connect/resolver are faked — no live scan."""

import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from scanner_lib import (
    RateLimiter,
    ScanError,
    ScanReport,
    Scope,
    ScopeError,
    normalize_target,
    parse_ports,
    run_scan,
)


# --- target / port parsing ------------------------------------------------ #
def test_normalize_target_ip_and_hostname():
    assert normalize_target(" 10.0.0.5 ") == "10.0.0.5"
    assert normalize_target("Example.COM") == "example.com"


def test_normalize_target_empty():
    with pytest.raises(ValueError):
        normalize_target("   ")


@pytest.mark.parametrize("spec,expected", [
    ("1-5", [1, 2, 3, 4, 5]),
    ("22,80,443", [22, 80, 443]),
    ("443,22,443,80", [22, 80, 443]),      # dedup + sort
    ("22-24,80", [22, 23, 24, 80]),
])
def test_parse_ports(spec, expected):
    assert parse_ports(spec) == expected


@pytest.mark.parametrize("spec", ["", "0-10", "1-70000", "10-5", "abc"])
def test_parse_ports_rejects_bad(spec):
    with pytest.raises(ValueError):
        parse_ports(spec)


# --- scope ---------------------------------------------------------------- #
def test_scope_ip_in_cidr():
    scope = Scope.from_entries(["10.0.0.0/24", "192.168.1.5"])
    assert scope.check("10.0.0.7") == "10.0.0.7"
    assert scope.check("192.168.1.5") == "192.168.1.5"


def test_scope_ip_out_of_range_rejected():
    scope = Scope.from_entries(["10.0.0.0/24"])
    with pytest.raises(ScopeError):
        scope.check("10.0.1.7")


def test_scope_hostname_exact_only():
    scope = Scope.from_entries(["lab.example.com", "10.0.0.0/24"])
    assert scope.check("lab.example.com") == "lab.example.com"
    # A different hostname is refused, and never resolved to bypass scope.
    with pytest.raises(ScopeError):
        scope.check("evil.example.com")
    # A hostname is NOT matched against IP/CIDR entries (no DNS).
    with pytest.raises(ScopeError):
        scope.check("host-not-listed.com")


def test_scope_from_file(tmp_path):
    f = tmp_path / "scope.txt"
    f.write_text("# hosts\n10.0.0.0/24\nlab.example.com # inline\n\n")
    scope = Scope.from_file(f)
    assert scope.check("10.0.0.99") == "10.0.0.99"
    assert scope.check("lab.example.com") == "lab.example.com"


def test_scope_from_empty_file(tmp_path):
    f = tmp_path / "scope.txt"
    f.write_text("# only comments\n")
    with pytest.raises(ScopeError):
        Scope.from_file(f)


def test_scope_missing_file(tmp_path):
    with pytest.raises(ScopeError):
        Scope.from_file(tmp_path / "nope.txt")


# --- rate limiter --------------------------------------------------------- #
def test_rate_limiter_zero_never_sleeps():
    slept = []
    rl = RateLimiter(0.0, sleep=slept.append)
    rl.wait()
    rl.wait()
    assert slept == []


def test_rate_limiter_spaces_calls():
    slept = []
    clock = iter([0.0, 0.0, 0.0])  # both calls at t=0
    rl = RateLimiter(1.0, sleep=slept.append, clock=lambda: next(clock))
    rl.wait()             # first: reserves slot, no sleep
    rl.wait()             # second: must wait ~1.0
    assert slept and round(slept[0], 3) == 1.0


# --- scanning ------------------------------------------------------------- #
def open_only(open_set):
    """Fake connect: returns 0 (open) for ports in open_set, else 1."""
    return lambda host, port, timeout: 0 if port in open_set else 1


def test_run_scan_finds_open_ports():
    report = ScanReport(target="10.0.0.5")
    run_scan(
        "10.0.0.5", parse_ports("1-100"), report,
        connect=open_only({22, 80}),
        resolver=lambda h: None,
        concurrency=8,
    )
    assert report.open_ports == [22, 80]
    assert report.ports_scanned == 100
    assert report.errors == []


def test_run_scan_no_open_ports():
    report = ScanReport(target="10.0.0.5")
    run_scan(
        "10.0.0.5", parse_ports("1-10"), report,
        connect=open_only(set()),
        resolver=lambda h: None,
    )
    assert report.open_ports == []
    assert "No open ports" in report.to_text()


def test_run_scan_unresolvable_host_records_error():
    def bad_resolver(host):
        raise ScanError("could not resolve")

    report = ScanReport(target="nope.invalid")
    run_scan(
        "nope.invalid", parse_ports("1-10"), report,
        connect=open_only({22}),
        resolver=bad_resolver,
    )
    assert report.open_ports == []
    assert any("could not resolve" in e for e in report.errors)


def test_run_scan_connect_error_isolated_per_port():
    def flaky(host, port, timeout):
        if port == 5:
            raise OSError("boom")
        return 0 if port == 22 else 1

    report = ScanReport(target="10.0.0.5")
    run_scan(
        "10.0.0.5", parse_ports("1-30"), report,
        connect=flaky, resolver=lambda h: None,
    )
    assert 22 in report.open_ports          # scan continued past the error
    assert any("port 5" in e for e in report.errors)


def test_run_scan_dry_run_makes_no_calls():
    tripped = {"connect": 0, "resolve": 0}

    def connect(h, p, t):
        tripped["connect"] += 1
        return 1

    def resolver(h):
        tripped["resolve"] += 1

    report = ScanReport(target="10.0.0.5", dry_run=True)
    run_scan(
        "10.0.0.5", parse_ports("1-1000"), report,
        connect=connect, resolver=resolver, dry_run=True,
    )
    assert tripped == {"connect": 0, "resolve": 0}
    assert report.ports_scanned == 1000
    assert any(e.startswith("dry-run:") for e in report.errors)


def test_run_scan_clamps_concurrency():
    # concurrency above MAX is clamped (no crash); result still correct.
    report = ScanReport(target="10.0.0.5")
    run_scan(
        "10.0.0.5", parse_ports("20-25"), report,
        connect=open_only({22}), resolver=lambda h: None,
        concurrency=100000,
    )
    assert report.open_ports == [22]

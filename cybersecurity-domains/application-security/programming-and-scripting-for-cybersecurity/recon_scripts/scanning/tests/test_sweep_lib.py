"""Unit tests for sweep_lib. The pinger is faked — no packets sent."""

import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from scanner_lib import Scope, ScopeError
from sweep_lib import (
    MAX_SWEEP_HOSTS,
    SweepError,
    SweepReport,
    check_all_in_scope,
    expand_targets,
    run_sweep,
)


# --- target expansion ----------------------------------------------------- #
def test_expand_cidr_excludes_network_and_broadcast():
    hosts = expand_targets("10.6.6.0/29")   # .0 net, .7 broadcast
    assert hosts == [f"10.6.6.{i}" for i in range(1, 7)]


def test_expand_single_ip():
    assert expand_targets("10.6.6.5") == ["10.6.6.5"]
    assert expand_targets("10.6.6.5/32") == ["10.6.6.5"]


def test_expand_dashed_range_inclusive():
    assert expand_targets("10.6.6.10-10.6.6.12") == [
        "10.6.6.10", "10.6.6.11", "10.6.6.12"
    ]


def test_expand_reversed_range_rejected():
    with pytest.raises(SweepError):
        expand_targets("10.6.6.20-10.6.6.10")


def test_expand_too_large_rejected():
    with pytest.raises(SweepError):
        expand_targets("10.0.0.0/8")           # ~16M hosts
    with pytest.raises(SweepError):
        expand_targets("10.0.0.0-10.255.255.255")


def test_expand_invalid_rejected():
    with pytest.raises(SweepError):
        expand_targets("not-an-ip")
    with pytest.raises(SweepError):
        expand_targets("")


def test_max_sweep_hosts_boundary():
    # A /16 is exactly MAX_SWEEP_HOSTS addresses; must not raise on sizing.
    hosts = expand_targets("10.6.0.0/16")
    assert len(hosts) == MAX_SWEEP_HOSTS - 2   # minus net + broadcast


# --- whole-range scope gate ---------------------------------------------- #
def test_check_all_in_scope_passes_when_all_in():
    scope = Scope.from_entries(["10.6.6.0/24"])
    check_all_in_scope(expand_targets("10.6.6.0/28"), scope)  # no raise


def test_check_all_in_scope_refuses_if_any_out():
    scope = Scope.from_entries(["10.6.6.0/28"])   # only .1-.14 in scope
    with pytest.raises(ScopeError) as exc:
        check_all_in_scope(expand_targets("10.6.6.0/24"), scope)
    assert "NOT in scope" in str(exc.value)
    assert "Refusing the entire sweep" in str(exc.value)


# --- sweeping ------------------------------------------------------------- #
def up_set(up):
    return lambda ip, timeout: ip in up


def test_run_sweep_finds_up_hosts_sorted():
    report = SweepReport(target="10.6.6.0/29")
    run_sweep(
        expand_targets("10.6.6.0/29"), report,
        pinger=up_set({"10.6.6.3", "10.6.6.1"}),
        concurrency=4,
    )
    assert report.up == ["10.6.6.1", "10.6.6.3"]   # numeric sort
    assert report.hosts_total == 6
    assert report.down_count == 4


def test_run_sweep_no_hosts_up():
    report = SweepReport(target="10.6.6.0/30")
    run_sweep(expand_targets("10.6.6.0/30"), report, pinger=up_set(set()))
    assert report.up == []
    assert "No hosts responded" in report.to_text()


def test_run_sweep_pinger_error_isolated():
    def flaky(ip, timeout):
        if ip == "10.6.6.2":
            raise OSError("ping broke")
        return ip == "10.6.6.1"

    report = SweepReport(target="10.6.6.0/29")
    run_sweep(expand_targets("10.6.6.0/29"), report, pinger=flaky)
    assert "10.6.6.1" in report.up            # sweep continued
    assert any("10.6.6.2" in e for e in report.errors)


def test_run_sweep_dry_run_sends_nothing():
    pinged = {"n": 0}

    def pinger(ip, timeout):
        pinged["n"] += 1
        return True

    report = SweepReport(target="10.6.6.0/24", dry_run=True)
    run_sweep(expand_targets("10.6.6.0/24"), report, pinger=pinger, dry_run=True)
    assert pinged["n"] == 0
    assert report.hosts_total == 254
    assert any(e.startswith("dry-run:") for e in report.errors)


def test_run_sweep_clamps_concurrency():
    report = SweepReport(target="10.6.6.0/29")
    run_sweep(
        expand_targets("10.6.6.0/29"), report,
        pinger=up_set({"10.6.6.1"}), concurrency=999999,
    )
    assert report.up == ["10.6.6.1"]


def test_report_json_includes_down_count():
    import json
    report = SweepReport(target="10.6.6.0/30", hosts_total=2, up=["10.6.6.1"])
    data = json.loads(report.to_json())
    assert data["down_count"] == 1

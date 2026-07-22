"""End-to-end CLI tests for basic_ping_sweep. Pinger mocked — no packets."""

import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

import basic_ping_sweep
import sweep_lib


@pytest.fixture
def scope_file(tmp_path):
    f = tmp_path / "scope.txt"
    f.write_text("10.6.6.0/24\n")
    return str(f)


@pytest.fixture(autouse=True)
def no_real_ping(monkeypatch):
    """Any real ping attempt fails the test."""
    def boom(ip, timeout):
        raise AssertionError("real ping attempted in a test!")

    monkeypatch.setattr(sweep_lib, "default_pinger", boom)


def test_no_target_returns_2():
    assert basic_ping_sweep.main([]) == 2


def test_bad_target_returns_2(scope_file):
    rc = basic_ping_sweep.main(
        ["not-an-ip", "--scope-file", scope_file, "--yes"]
    )
    assert rc == 2


def test_range_partly_out_of_scope_refused(scope_file, caplog):
    # 10.6.7.0/24 is entirely outside the 10.6.6.0/24 scope.
    rc = basic_ping_sweep.main(
        ["10.6.7.0/28", "--scope-file", scope_file, "--yes"]
    )
    assert rc == 3
    assert "Refusing the entire sweep" in caplog.text


def test_no_scope_no_auth_refused(caplog):
    rc = basic_ping_sweep.main(["10.6.6.0/29", "--yes"])
    assert rc == 2
    assert "no scope provided" in caplog.text


def test_dry_run_sends_nothing(scope_file, capsys):
    rc = basic_ping_sweep.main(
        ["10.6.6.0/24", "--scope-file", scope_file, "--yes", "--dry-run"]
    )
    assert rc == 0
    out = capsys.readouterr().out
    assert "dry-run:" in out and "True" in out


def test_in_scope_sweep_with_mocked_pinger(scope_file, monkeypatch, capsys):
    monkeypatch.setattr(
        sweep_lib, "default_pinger",
        lambda ip, timeout: ip == "10.6.6.1",
    )
    rc = basic_ping_sweep.main(
        ["10.6.6.0/29", "--scope-file", scope_file, "--yes", "--format", "json"]
    )
    assert rc == 0
    assert "10.6.6.1" in capsys.readouterr().out


def test_operator_declines(scope_file, monkeypatch):
    monkeypatch.setattr("builtins.input", lambda *_: "n")
    rc = basic_ping_sweep.main(["10.6.6.0/29", "--scope-file", scope_file])
    assert rc == 1

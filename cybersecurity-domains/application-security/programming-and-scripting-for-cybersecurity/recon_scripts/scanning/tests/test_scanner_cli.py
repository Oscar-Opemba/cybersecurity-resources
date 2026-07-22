"""End-to-end CLI tests with connect/resolver mocked. No live scan."""

import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

import quick_scanner
import scanner_lib


@pytest.fixture
def scope_file(tmp_path):
    f = tmp_path / "scope.txt"
    f.write_text("10.0.0.0/24\nlab.example.com\n")
    return str(f)


@pytest.fixture(autouse=True)
def no_real_network(monkeypatch):
    """Guarantee no test can open a real socket or resolve a real host."""
    def boom_connect(host, port, timeout):
        raise AssertionError("real connect() attempted in a test!")

    def noop_resolver(host):
        return None

    monkeypatch.setattr(scanner_lib, "default_connect", boom_connect)
    monkeypatch.setattr(scanner_lib, "default_resolver", noop_resolver)


def test_no_target_returns_2():
    assert quick_scanner.main([]) == 2


def test_bad_ports_returns_2(scope_file):
    rc = quick_scanner.main(
        ["10.0.0.5", "--ports", "abc", "--scope-file", scope_file, "--yes"]
    )
    assert rc == 2


def test_out_of_scope_refused(scope_file, caplog):
    rc = quick_scanner.main(
        ["10.9.9.9", "--scope-file", scope_file, "--yes"]
    )
    assert rc == 3
    assert "NOT within any in-scope network" in caplog.text


def test_no_scope_no_auth_refused(caplog):
    rc = quick_scanner.main(["10.0.0.5", "--yes"])
    assert rc == 2
    assert "no scope provided" in caplog.text


def test_dry_run_makes_no_network(scope_file, monkeypatch, capsys):
    # default_connect is already the AssertionError bomb; dry-run must not hit it.
    rc = quick_scanner.main(
        ["10.0.0.5", "--ports", "1-1000", "--scope-file", scope_file,
         "--yes", "--dry-run"]
    )
    assert rc == 0
    out = capsys.readouterr().out
    assert "dry-run:" in out and "True" in out


def test_in_scope_scan_with_mocked_connect(scope_file, monkeypatch, capsys):
    monkeypatch.setattr(
        scanner_lib, "default_connect",
        lambda host, port, timeout: 0 if port == 22 else 1,
    )
    rc = quick_scanner.main(
        ["10.0.0.5", "--ports", "20-25", "--scope-file", scope_file,
         "--yes", "--format", "json"]
    )
    assert rc == 0
    assert '"open_ports"' in capsys.readouterr().out


def test_operator_declines(scope_file, monkeypatch):
    monkeypatch.setattr("builtins.input", lambda *_: "n")
    rc = quick_scanner.main(["10.0.0.5", "--scope-file", scope_file])
    assert rc == 1

"""End-to-end CLI tests for python_nmap. Scan fn mocked — nmap never runs."""

import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

import nmap_lib
import python_nmap


@pytest.fixture
def scope_file(tmp_path):
    f = tmp_path / "scope.txt"
    f.write_text("10.0.0.0/24\n")
    return str(f)


@pytest.fixture(autouse=True)
def no_real_nmap(monkeypatch):
    """Any real nmap invocation fails the test."""
    def boom(hosts, ports):
        raise AssertionError("real nmap invoked in a test!")

    monkeypatch.setattr(nmap_lib, "default_scan_fn", boom)


def test_no_target_returns_2():
    assert python_nmap.main([]) == 2


def test_bad_ports_returns_2(scope_file):
    rc = python_nmap.main(
        ["10.0.0.5", "--ports", "abc", "--scope-file", scope_file, "--yes"]
    )
    assert rc == 2


def test_out_of_scope_refused(scope_file, caplog):
    rc = python_nmap.main(
        ["10.9.9.0/29", "--scope-file", scope_file, "--yes"]
    )
    assert rc == 3
    assert "Refusing" in caplog.text


def test_no_scope_no_auth_refused(caplog):
    rc = python_nmap.main(["10.0.0.5", "--yes"])
    assert rc == 2
    assert "no scope provided" in caplog.text


def test_dry_run_does_not_scan(scope_file, capsys):
    rc = python_nmap.main(
        ["10.0.0.0/29", "--scope-file", scope_file, "--yes", "--dry-run"]
    )
    assert rc == 0
    out = capsys.readouterr().out
    assert "dry-run:" in out and "True" in out


def test_in_scope_scan_with_mocked_backend(scope_file, monkeypatch, capsys):
    monkeypatch.setattr(
        nmap_lib, "default_scan_fn",
        lambda hosts, ports: {"10.0.0.5": [(22, "open")]},
    )
    rc = python_nmap.main(
        ["10.0.0.5", "--ports", "22", "--scope-file", scope_file,
         "--yes", "--format", "json"]
    )
    assert rc == 0
    assert '"state": "open"' in capsys.readouterr().out


def test_backend_missing_returns_4(scope_file, monkeypatch):
    def broken(hosts, ports):
        raise nmap_lib.NmapError("python-nmap not installed")

    monkeypatch.setattr(nmap_lib, "default_scan_fn", broken)
    rc = python_nmap.main(
        ["10.0.0.5", "--ports", "22", "--scope-file", scope_file, "--yes"]
    )
    assert rc == 4


def test_operator_declines(scope_file, monkeypatch):
    monkeypatch.setattr("builtins.input", lambda *_: "n")
    rc = python_nmap.main(["10.0.0.5", "--scope-file", scope_file])
    assert rc == 1

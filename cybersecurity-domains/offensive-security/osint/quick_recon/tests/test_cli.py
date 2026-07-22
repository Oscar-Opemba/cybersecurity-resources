"""End-to-end CLI tests with search fully mocked. No network activity."""

import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

import quick_recon


@pytest.fixture
def scope_file(tmp_path):
    f = tmp_path / "scope.txt"
    f.write_text("example.com\n")
    return str(f)


def test_no_target_returns_2():
    assert quick_recon.main([]) == 2


def test_out_of_scope_target_refused(scope_file, caplog):
    rc = quick_recon.main(["evil.com", "--scope-file", scope_file, "--yes"])
    assert rc == 3
    assert "NOT in scope" in caplog.text


def test_no_scope_and_no_authorization_flag_refused(caplog):
    rc = quick_recon.main(["example.com", "--yes"])
    assert rc == 2
    assert "no scope provided" in caplog.text


def test_operator_declines_confirmation(scope_file, monkeypatch):
    monkeypatch.setattr(quick_recon, "confirm", lambda *a, **k: False)
    rc = quick_recon.main(["example.com", "--scope-file", scope_file])
    assert rc == 1


def test_dry_run_makes_no_network_call(scope_file, monkeypatch, capsys):
    # If _real_search were ever called in dry-run, this would blow up.
    monkeypatch.setattr(
        quick_recon, "_real_search",
        lambda args: (_ for _ in ()).throw(AssertionError("network in dry-run!")),
    )
    rc = quick_recon.main(
        ["example.com", "--scope-file", scope_file, "--yes", "--dry-run"]
    )
    assert rc == 0
    out = capsys.readouterr().out
    assert "dry-run:" in out and "True" in out


def test_in_scope_run_with_mocked_search(scope_file, monkeypatch, capsys):
    monkeypatch.setattr(
        quick_recon, "_real_search",
        lambda args: (lambda q: ["https://found.example.com/x"]),
    )
    rc = quick_recon.main(
        ["example.com", "--scope-file", scope_file, "--yes",
         "--format", "json", "--pause", "0"]
    )
    assert rc == 0
    out = capsys.readouterr().out
    assert "found.example.com" in out


def test_authorized_flag_allows_run_without_scope(monkeypatch, capsys):
    monkeypatch.setattr(
        quick_recon, "_real_search",
        lambda args: (lambda q: []),
    )
    rc = quick_recon.main(
        ["example.com", "--i-am-authorized", "--yes", "--pause", "0"]
    )
    assert rc == 0


def test_api_backend_missing_creds_returns_4(scope_file, monkeypatch):
    # No GOOGLE_API_KEY / GOOGLE_CSE_ID -> backend build fails -> exit 4.
    monkeypatch.delenv("GOOGLE_API_KEY", raising=False)
    monkeypatch.delenv("GOOGLE_CSE_ID", raising=False)
    rc = quick_recon.main(
        ["example.com", "--scope-file", scope_file, "--yes",
         "--backend", "api", "--pause", "0"]
    )
    assert rc == 4

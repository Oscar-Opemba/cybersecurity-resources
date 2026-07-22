"""Unit tests for recon_lib. Search is faked — no live network."""

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from recon_lib import CHECKS, Check, normalize_result, run_check, run_recon
from report import Report
from safety import RateLimiter


def fake_search(results):
    """Return a SearchFn that always yields the given results."""
    return lambda query: list(results)


def test_normalize_result_reduces_to_host():
    assert normalize_result("https://a.example.com/deep/path?x=1") == \
        "https://a.example.com/"
    assert normalize_result("not a url") == "not a url"


def test_check_query_formatting():
    c = Check("cat", "desc", "site:{target} foo")
    assert c.query("example.com") == "site:example.com foo"


def test_run_check_dedupes():
    search = fake_search([
        "https://a.example.com/1",
        "https://a.example.com/2",   # same host -> deduped
        "https://b.example.com/",
    ])
    urls, errors = run_check(CHECKS[0], "example.com", search)
    assert urls == ["https://a.example.com/", "https://b.example.com/"]
    assert errors == []


def test_run_check_retries_then_succeeds():
    calls = {"n": 0}

    def flaky(query):
        calls["n"] += 1
        if calls["n"] < 2:
            raise ConnectionError("boom")
        return ["https://ok.example.com/"]

    urls, errors = run_check(
        CHECKS[0], "example.com", flaky, retries=2, sleep=lambda _: None
    )
    assert urls == ["https://ok.example.com/"]
    assert errors == []
    assert calls["n"] == 2


def test_run_check_gives_up_and_records_error():
    def always_fails(query):
        raise TimeoutError("nope")

    urls, errors = run_check(
        CHECKS[0], "example.com", always_fails, retries=1, sleep=lambda _: None
    )
    assert urls == []
    assert len(errors) == 1
    assert "query failed" in errors[0]


def test_run_recon_populates_report():
    search = fake_search(["https://x.example.com/"])
    report = Report(target="example.com")
    run_recon("example.com", search, report, sleep=lambda _: None)
    # One finding per check, all deduped to the same host.
    assert len(report.findings) == len(CHECKS)
    assert all(f.url == "https://x.example.com/" for f in report.findings)
    assert report.errors == []


def test_run_recon_dry_run_makes_no_calls():
    called = {"n": 0}

    def tripwire(query):
        called["n"] += 1
        return []

    report = Report(target="example.com", dry_run=True)
    run_recon("example.com", tripwire, report, dry_run=True)
    assert called["n"] == 0            # search never invoked
    assert report.findings == []
    # Every check is recorded as a dry-run note.
    assert len(report.errors) == len(CHECKS)
    assert all(e.startswith("dry-run:") for e in report.errors)


def test_run_recon_respects_rate_limiter():
    waits = {"n": 0}

    class CountingLimiter(RateLimiter):
        def wait(self):
            waits["n"] += 1
            return 0.0

    search = fake_search(["https://x.example.com/"])
    report = Report(target="example.com")
    run_recon(
        "example.com", search, report,
        limiter=CountingLimiter(0), sleep=lambda _: None,
    )
    assert waits["n"] == len(CHECKS)

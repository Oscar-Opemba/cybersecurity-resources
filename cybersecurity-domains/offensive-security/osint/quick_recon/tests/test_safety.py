"""Unit tests for the safety rails. No network activity."""

import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from safety import RateLimiter, Scope, ScopeError, confirm, normalize_domain


@pytest.mark.parametrize("raw,expected", [
    ("example.com", "example.com"),
    ("  Example.COM ", "example.com"),
    ("http://example.com/path?q=1", "example.com"),
    ("https://www.example.com", "example.com"),
    ("sub.example.com", "sub.example.com"),
    ("example.com:8443", "example.com"),
])
def test_normalize_domain(raw, expected):
    assert normalize_domain(raw) == expected


def test_normalize_domain_rejects_empty():
    with pytest.raises(ValueError):
        normalize_domain("")


def test_scope_exact_and_subdomain_in_scope():
    scope = Scope(domains=["example.com"])
    assert scope.check("example.com") == "example.com"
    assert scope.check("api.example.com") == "api.example.com"
    assert scope.check("http://deep.api.example.com/x") == "deep.api.example.com"


def test_scope_rejects_out_of_scope():
    scope = Scope(domains=["example.com"])
    with pytest.raises(ScopeError):
        scope.check("evil.com")
    # A look-alike that merely ends with the string but is a different domain.
    with pytest.raises(ScopeError):
        scope.check("notexample.com")


def test_scope_empty_allows_nothing():
    scope = Scope(domains=[])
    with pytest.raises(ScopeError):
        scope.check("example.com")


def test_scope_from_file(tmp_path):
    f = tmp_path / "scope.txt"
    f.write_text("# comment\nexample.com\n\n  example.org # inline\n")
    scope = Scope.from_file(f)
    assert scope.domains == ["example.com", "example.org"]
    assert scope.check("mail.example.org") == "mail.example.org"


def test_scope_from_missing_file(tmp_path):
    with pytest.raises(ScopeError):
        Scope.from_file(tmp_path / "nope.txt")


def test_scope_from_empty_file(tmp_path):
    f = tmp_path / "scope.txt"
    f.write_text("# only comments\n\n")
    with pytest.raises(ScopeError):
        Scope.from_file(f)


def test_rate_limiter_first_call_no_wait():
    slept = []
    rl = RateLimiter(1.0, sleep=slept.append, clock=lambda: 100.0)
    assert rl.wait() == 0.0
    assert slept == []


def test_rate_limiter_enforces_interval():
    clock_values = iter([100.0, 100.2, 100.2])  # second call 0.2s later
    slept = []
    rl = RateLimiter(
        1.0, sleep=slept.append, clock=lambda: next(clock_values)
    )
    rl.wait()  # primes _last = 100.0
    slept_secs = rl.wait()  # elapsed 0.2, should sleep 0.8
    assert round(slept_secs, 3) == 0.8
    assert slept == [pytest.approx(0.8)]


def test_confirm_assume_yes():
    assert confirm("go?", assume_yes=True) is True


@pytest.mark.parametrize("answer,expected", [
    ("y", True), ("yes", True), ("Y", True),
    ("n", False), ("", False), ("nope", False),
])
def test_confirm_prompt(answer, expected):
    assert confirm("go?", input_fn=lambda _: answer) is expected

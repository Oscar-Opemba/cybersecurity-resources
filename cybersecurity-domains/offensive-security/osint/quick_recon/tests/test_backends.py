"""Unit tests for search backends. HTTP is faked — no live network."""

import logging
import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from backends import (
    API_KEY_ENV,
    CSE_ID_ENV,
    BackendError,
    api_backend,
    build_backend,
)


class FakeResponse:
    def __init__(self, payload, status_code=200):
        self._payload = payload
        self.status_code = status_code

    def json(self):
        return self._payload


def test_api_backend_requires_credentials():
    with pytest.raises(BackendError):
        api_backend("", "cse")
    with pytest.raises(BackendError):
        api_backend("key", "")


def test_api_backend_returns_links():
    def fake_get(url, params=None, timeout=10):
        # One page of two results, then an empty page to stop pagination.
        if params["start"] == 1:
            return FakeResponse({"items": [
                {"link": "https://a.example.com/"},
                {"link": "https://b.example.com/"},
            ]})
        return FakeResponse({"items": []})

    search = api_backend("key", "cse", max_results=30, http_get=fake_get)
    assert list(search("site:example.com")) == [
        "https://a.example.com/", "https://b.example.com/"
    ]


def test_api_backend_respects_max_results():
    def fake_get(url, params=None, timeout=10):
        return FakeResponse({"items": [
            {"link": f"https://h{params['start']}.example.com/"},
        ] * 5})

    search = api_backend("key", "cse", max_results=3, http_get=fake_get)
    assert len(list(search("q"))) == 3


def test_api_backend_raises_on_http_error():
    def fake_get(url, params=None, timeout=10):
        return FakeResponse({}, status_code=429)

    search = api_backend("key", "cse", http_get=fake_get)
    with pytest.raises(BackendError):
        list(search("q"))


def test_api_backend_never_logs_credentials(caplog):
    def fake_get(url, params=None, timeout=10):
        return FakeResponse({"items": []})

    with caplog.at_level(logging.DEBUG, logger="quick_recon"):
        search = api_backend("SUPERSECRETKEY", "cse", http_get=fake_get)
        list(search("q"))
    assert "SUPERSECRETKEY" not in caplog.text


def test_build_backend_dispatch_and_env():
    def fake_get(url, params=None, timeout=10):
        return FakeResponse({"items": []})

    # api backend built from an injected env mapping.
    search = build_backend(
        "api", env={API_KEY_ENV: "k", CSE_ID_ENV: "c"}
    )
    assert callable(search)


def test_build_backend_api_missing_env_raises():
    with pytest.raises(BackendError):
        build_backend("api", env={})


def test_build_backend_unknown_name():
    with pytest.raises(BackendError):
        build_backend("nope", env={})

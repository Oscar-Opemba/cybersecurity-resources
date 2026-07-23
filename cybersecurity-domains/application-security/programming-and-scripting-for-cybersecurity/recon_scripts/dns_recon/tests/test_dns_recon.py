"""Unit tests for the DNS recon tools. Resolvers injected — no DNS/WHOIS."""

import json
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

import cloud_provider
import mx_record_extractor as mx


# --- mx_record_extractor -------------------------------------------------- #
def test_get_mx_records_sorted_by_preference():
    def fake(domain):
        return [("mail2.example.com.", 20), ("mail1.example.com.", 10)]

    recs = mx.get_mx_records("example.com", resolver=fake)
    assert [r["preference"] for r in recs] == [10, 20]
    assert recs[0]["exchange"] == "mail1.example.com."


def test_get_mx_records_empty():
    assert mx.get_mx_records("example.com", resolver=lambda d: []) == []


def test_mx_resolver_error_propagates():
    def boom(domain):
        raise mx.MxError("NXDOMAIN")

    try:
        mx.get_mx_records("nope.invalid", resolver=boom)
        assert False, "expected MxError"
    except mx.MxError:
        pass


def test_mx_main_no_domain_returns_2():
    assert mx.main([]) == 2


def test_mx_main_error_returns_4(monkeypatch):
    def boom(domain):
        raise mx.MxError("NXDOMAIN")

    monkeypatch.setattr(mx, "_default_resolver", boom)
    assert mx.main(["nope.invalid"]) == 4


def test_mx_main_json(monkeypatch, capsys):
    monkeypatch.setattr(
        mx, "_default_resolver", lambda d: [("mail.example.com.", 10)]
    )
    rc = mx.main(["example.com", "--format", "json"])
    assert rc == 0
    data = json.loads(capsys.readouterr().out)
    assert data["mx"][0]["exchange"] == "mail.example.com."


# --- cloud_provider ------------------------------------------------------- #
def test_is_major_cloud_provider():
    assert cloud_provider.is_major_cloud_provider("Amazon Technologies Inc.")
    assert cloud_provider.is_major_cloud_provider("Google LLC")
    assert not cloud_provider.is_major_cloud_provider("Acme Corp")


def test_analyze_unresolvable():
    result = cloud_provider.analyze("nope.invalid", resolver=lambda d: None)
    assert result["ip"] is None
    assert result["cloud_provider"] is None


def test_analyze_cloud_hit():
    result = cloud_provider.analyze(
        "example.com",
        resolver=lambda d: "52.1.2.3",
        whois_org=lambda ip: "Amazon Technologies Inc.",
    )
    assert result["ip"] == "52.1.2.3"
    assert result["cloud_provider"] is True


def test_analyze_non_cloud():
    result = cloud_provider.analyze(
        "example.com",
        resolver=lambda d: "1.2.3.4",
        whois_org=lambda ip: "Acme Hosting",
    )
    assert result["cloud_provider"] is False


def test_analyze_no_whois():
    result = cloud_provider.analyze(
        "example.com",
        resolver=lambda d: "1.2.3.4",
        whois_org=lambda ip: None,
    )
    assert result["org"] is None
    assert result["cloud_provider"] is None


def test_cloud_main_no_domain_returns_2():
    assert cloud_provider.main([]) == 2


def test_cloud_main_json(monkeypatch, capsys):
    monkeypatch.setattr(cloud_provider, "_default_resolver", lambda d: "52.1.2.3")
    monkeypatch.setattr(cloud_provider, "_default_whois_org", lambda ip: "Amazon")
    rc = cloud_provider.main(["example.com", "--format", "json"])
    assert rc == 0
    data = json.loads(capsys.readouterr().out)
    assert data["cloud_provider"] is True

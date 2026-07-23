"""Unit tests for the certificate tools. Network fetch/probe injected."""

import json
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

import check_weak_crypto as cwc
import get_cert_info as gci


# --- get_cert_info -------------------------------------------------------- #
def test_get_certificate_info_returns_cert():
    cert = {"subject": ((("commonName", "example.com"),),), "version": 3}
    result = gci.get_certificate_info(
        "example.com", fetch=lambda h, p: cert
    )
    assert result["version"] == 3


def test_get_certificate_info_error():
    def boom(h, p):
        raise TimeoutError("timed out")

    try:
        gci.get_certificate_info("example.com", fetch=boom)
        assert False, "expected CertError"
    except gci.CertError:
        pass


def test_gci_main_no_domain_returns_2():
    assert gci.main([]) == 2


def test_gci_main_error_returns_4(monkeypatch):
    def boom(h, p):
        raise ConnectionRefusedError("refused")

    monkeypatch.setattr(gci, "_default_fetch", boom)
    assert gci.main(["example.com"]) == 4


def test_gci_main_json(monkeypatch, capsys):
    monkeypatch.setattr(gci, "_default_fetch", lambda h, p: {"version": 3})
    rc = gci.main(["example.com", "--format", "json"])
    assert rc == 0
    assert json.loads(capsys.readouterr().out)["version"] == 3


# --- check_weak_crypto ---------------------------------------------------- #
def test_check_weak_crypto_reports_accepted():
    # Server accepts TLSv1 but rejects the others.
    def prober(host, port, proto):
        return proto == "TLSv1"

    result = cwc.check_weak_crypto("example.com", prober=prober)
    assert result["weak_protocols_accepted"] == ["TLSv1"]
    assert result["untested"] == []


def test_check_weak_crypto_all_rejected():
    result = cwc.check_weak_crypto(
        "example.com", prober=lambda h, p, proto: False
    )
    assert result["weak_protocols_accepted"] == []


def test_check_weak_crypto_untested_recorded():
    def prober(host, port, proto):
        if proto == "SSLv3":
            raise OSError("openssl refuses SSLv3")
        return False

    result = cwc.check_weak_crypto("example.com", prober=prober)
    assert any("SSLv3" in u for u in result["untested"])


def test_cwc_main_no_domain_returns_2():
    assert cwc.main([]) == 2


def test_cwc_main_json(monkeypatch, capsys):
    monkeypatch.setattr(
        cwc, "_default_prober", lambda h, p, proto: proto == "TLSv1.1"
    )
    rc = cwc.main(["example.com", "--format", "json"])
    assert rc == 0
    data = json.loads(capsys.readouterr().out)
    assert data["weak_protocols_accepted"] == ["TLSv1.1"]

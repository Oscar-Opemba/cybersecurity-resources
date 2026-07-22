"""Unit tests for the report model. No network activity."""

import json
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from report import Report


def make_report():
    r = Report(target="example.com", scope=["example.com"])
    r.add("subdomains", "https://a.example.com/")
    r.add("subdomains", "https://b.example.com/")
    r.add("login_pages", "https://a.example.com/login")
    r.add_error("boom")
    return r


def test_categories_grouping():
    r = make_report()
    cats = r.categories()
    assert cats["subdomains"] == [
        "https://a.example.com/", "https://b.example.com/"
    ]
    assert cats["login_pages"] == ["https://a.example.com/login"]


def test_to_json_roundtrips():
    r = make_report()
    data = json.loads(r.to_json())
    assert data["target"] == "example.com"
    assert len(data["findings"]) == 3
    assert data["errors"] == ["boom"]


def test_to_csv_has_header_and_rows():
    r = make_report()
    lines = r.to_csv().strip().splitlines()
    assert lines[0] == "target,category,url"
    assert len(lines) == 4  # header + 3 findings


def test_to_text_includes_summary_and_findings():
    r = make_report()
    text = r.to_text()
    assert "quick_recon report for: example.com" in text
    assert "[subdomains] (2)" in text
    assert "https://a.example.com/login" in text
    assert "boom" in text


def test_to_text_clean_result_message():
    r = Report(target="example.com")
    assert "No findings" in r.to_text()

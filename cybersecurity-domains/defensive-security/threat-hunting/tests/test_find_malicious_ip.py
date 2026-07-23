"""Unit tests for find_malicious_ip. Local strings/files only — no network."""

import json
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

import find_malicious_ip as fmi


def test_search_lines_matches():
    lines = [
        "Jan 1 sshd: Accepted password from 10.0.0.5 port 22",
        "Jan 1 sshd: Accepted password from 8.8.8.8 port 22",
        "Jan 1 kernel: nothing here",
    ]
    result = fmi.search_lines(lines, {"10.0.0.5"})
    assert len(result.matches) == 1
    assert result.matches[0].ip == "10.0.0.5"
    assert result.matches[0].line_number == 1


def test_search_lines_multiple_ips_per_line():
    lines = ["src 1.2.3.4 -> dst 10.0.0.5 via 9.9.9.9"]
    result = fmi.search_lines(lines, {"1.2.3.4", "9.9.9.9"})
    assert sorted(m.ip for m in result.matches) == ["1.2.3.4", "9.9.9.9"]


def test_search_lines_clean():
    result = fmi.search_lines(["nothing bad here"], {"10.0.0.5"})
    assert result.matches == []
    assert "No known-bad IPs" in result.to_text()


def test_load_iocs(tmp_path):
    f = tmp_path / "iocs.txt"
    f.write_text("# bad ips\n10.0.0.5\n8.8.8.8 # a comment\n\n")
    assert fmi.load_iocs(str(f)) == {"10.0.0.5", "8.8.8.8"}


def test_report_formats():
    result = fmi.search_lines(["from 10.0.0.5"], {"10.0.0.5"})
    data = json.loads(result.to_json())
    assert data["matches"][0]["ip"] == "10.0.0.5"
    assert result.to_csv().splitlines()[0] == "ip,line_number,line"


def test_main_no_logfile_returns_2():
    assert fmi.main([]) == 2


def test_main_no_iocs_returns_2(tmp_path):
    logf = tmp_path / "a.log"
    logf.write_text("from 10.0.0.5\n")
    assert fmi.main([str(logf)]) == 2


def test_main_end_to_end(tmp_path, capsys):
    logf = tmp_path / "a.log"
    logf.write_text("Jan 1 from 10.0.0.5\nJan 1 from 1.1.1.1\n")
    rc = fmi.main([str(logf), "--ip", "10.0.0.5", "--format", "json"])
    assert rc == 0
    data = json.loads(capsys.readouterr().out)
    assert len(data["matches"]) == 1


def test_main_missing_logfile_returns_2():
    assert fmi.main(["/no/such/file.log", "--ip", "10.0.0.5"]) == 2

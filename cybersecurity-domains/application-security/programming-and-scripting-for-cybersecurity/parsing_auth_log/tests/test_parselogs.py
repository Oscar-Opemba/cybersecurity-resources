"""Unit tests for ParseLogs pure parser functions. No files, no network."""

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

import ParseLogs as pl


def test_parse_ip():
    line = "Jan  1 10:00:00 host sshd[1]: Accepted password for bob from 203.0.113.9 port 22 ssh2"
    assert pl.ParseIP(line) == "203.0.113.9"


def test_parse_ip_none():
    assert pl.ParseIP("no address here") is None


def test_parse_usr_accepted():
    line = "Jan  1 10:00:00 host sshd[1]: Accepted password for alice from 10.0.0.1 port 22 ssh2"
    assert pl.ParseUsr(line) == "alice"


def test_parse_usr_invalid_user():
    line = "Jan  1 10:00:00 host sshd[1]: Failed password for invalid user hacker from 10.0.0.1"
    assert pl.ParseUsr(line) == "hacker"


def test_parse_date():
    line = "Jan  1 10:11:12 host sshd[1]: something"
    assert pl.ParseDate(line) == "Jan  1 10:11:12"


def test_parse_date_none():
    assert pl.ParseDate("not a syslog line") is None


def test_parse_cmd():
    line = "Jan  1 host sudo:  bob : COMMAND=/usr/bin/vi /etc/hosts"
    assert pl.ParseCmd(line) == "/usr/bin/vi /etc/hosts"


def test_parse_logs_end_to_end(tmp_path):
    logfile = tmp_path / "auth.log"
    logfile.write_text(
        "Jan  1 10:00:00 h sshd[1]: Accepted password for alice from 10.0.0.1 port 22 ssh2\n"
        "Jan  1 10:00:01 h sshd[1]: Failed password for bob from 10.0.0.2 port 22 ssh2\n"
    )
    logs = pl.ParseLogs(str(logfile))
    assert "alice" in logs
    assert "10.0.0.1" in logs["alice"].ips
    assert len(logs["alice"].succ_logs) == 1
    assert "bob" in logs
    assert len(logs["bob"].fail_logs) == 1


def test_parse_logs_missing_file_returns_none():
    assert pl.ParseLogs("/no/such/file.log") is None

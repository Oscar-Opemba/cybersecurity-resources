"""Unit tests for sensitive_file_scanner. Local filesystem only — no network."""

import json
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

import sensitive_file_scanner as sfs


def test_match_reason_pattern():
    assert sfs.match_reason("my_password.txt", sfs.DEFAULT_EXTENSIONS,
                            sfs.DEFAULT_PATTERNS) == "pattern:*password*"


def test_match_reason_extension():
    assert sfs.match_reason("server.pem", sfs.DEFAULT_EXTENSIONS,
                            sfs.DEFAULT_PATTERNS) == "extension:.pem"


def test_match_reason_case_insensitive():
    assert sfs.match_reason("SECRET.TXT", sfs.DEFAULT_EXTENSIONS,
                            sfs.DEFAULT_PATTERNS) == "pattern:*secret*"
    assert sfs.match_reason("KEY.PEM", sfs.DEFAULT_EXTENSIONS,
                            sfs.DEFAULT_PATTERNS) == "extension:.pem"


def test_match_reason_none():
    assert sfs.match_reason("readme.md", sfs.DEFAULT_EXTENSIONS,
                            sfs.DEFAULT_PATTERNS) is None


def _make_tree(tmp_path):
    (tmp_path / "a").mkdir()
    (tmp_path / "a" / "id_rsa.pem").write_text("x")
    (tmp_path / "a" / "notes.md").write_text("x")
    (tmp_path / "b").mkdir()
    (tmp_path / "b" / "my_secret_file.txt").write_text("x")
    (tmp_path / "b" / "image.png").write_text("x")
    return tmp_path


def test_scan_directory_finds_expected(tmp_path):
    _make_tree(tmp_path)
    result = sfs.scan_directory(str(tmp_path))
    reasons = sorted(f.reason for f in result.findings)
    assert reasons == ["extension:.pem", "pattern:*secret*"]
    assert result.errors == []


def test_scan_directory_clean(tmp_path):
    (tmp_path / "readme.md").write_text("x")
    result = sfs.scan_directory(str(tmp_path))
    assert result.findings == []
    assert "No sensitive files" in result.to_text()


def test_scan_directory_custom_extension(tmp_path):
    (tmp_path / "config.env").write_text("x")
    result = sfs.scan_directory(str(tmp_path), extensions=[".env"], patterns=[])
    assert len(result.findings) == 1
    assert result.findings[0].reason == "extension:.env"


def test_does_not_follow_symlinks_by_default(tmp_path):
    outside = tmp_path / "outside"
    outside.mkdir()
    (outside / "leak_secret.txt").write_text("x")
    tree = tmp_path / "tree"
    tree.mkdir()
    try:
        (tree / "link").symlink_to(outside, target_is_directory=True)
    except (OSError, NotImplementedError):
        return  # platform without symlink support
    # Default: symlink not followed -> the outside secret is NOT found.
    result = sfs.scan_directory(str(tree))
    assert result.findings == []
    # With follow-symlinks it IS found.
    result2 = sfs.scan_directory(str(tree), follow_symlinks=True)
    assert any("leak_secret" in f.path for f in result2.findings)


def test_report_formats(tmp_path):
    _make_tree(tmp_path)
    result = sfs.scan_directory(str(tmp_path))
    data = json.loads(result.to_json())
    assert len(data["findings"]) == 2
    csv_lines = result.to_csv().strip().splitlines()
    assert csv_lines[0] == "path,reason"
    assert len(csv_lines) == 3


def test_main_bad_directory_returns_2():
    assert sfs.main(["/nonexistent/path/xyz"]) == 2


def test_main_no_directory_returns_2():
    assert sfs.main([]) == 2


def test_main_json_output(tmp_path, capsys):
    _make_tree(tmp_path)
    rc = sfs.main([str(tmp_path), "--format", "json"])
    assert rc == 0
    assert '"findings"' in capsys.readouterr().out

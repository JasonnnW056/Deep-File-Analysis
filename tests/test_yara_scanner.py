from app.static_analysis.yara_scanner import get_rules
from app.static_analysis.yara_scanner import _severity_from_meta, analyze_yara
from app.static_analysis.scanner import scan_file, registered_analyzers

from unittest import mock
from app.static_analysis import yara_scanner

EICAR = b"X5O!P%@AP[4\\PZX54(P^)7CC)7}$EICAR-STANDARD-ANTIVIRUS-TEST-FILE!$H+H*"

def test_eicar_detected():
    matches = get_rules().match(data=EICAR)
    assert len(matches) > 0

def test_clean_data_not_flagged():
    assert get_rules().match(data=b"hello world") == []

def test_high_score_is_high():
    assert _severity_from_meta({"score": 80, "quality": 90}) == "high"


def test_low_quality_steps_severity_down():
    assert _severity_from_meta({"score": 80, "quality": 30}) == "medium"


def test_missing_score_defaults_to_medium():
    assert _severity_from_meta({}) == "medium"


def test_yara_is_registered():
    assert "yara" in registered_analyzers()


def test_clean_file_has_no_findings(tmp_path):
    f = tmp_path / "clean.txt"
    f.write_bytes(b"hello world")
    env = analyze_yara(f)
    assert env["status"] == "ok"
    assert env["findings"] == []


def test_missing_file_is_error_not_crash(tmp_path):
    env = analyze_yara(tmp_path / "nope.bin")
    assert env["status"] == "error"


def test_full_scan_includes_yara(tmp_path):
    f = tmp_path / "clean.txt"
    f.write_bytes(b"hello world")
    report = scan_file(f)
    assert report["analyzers"]["yara"]["status"] == "ok"

def test_timeout_is_error_not_finding():
    with mock.patch.object(yara_scanner, "scan_file",
                           return_value=[{"rule": "SCAN_TIMEOUT", "tags": [], "meta": {}}]):
        r = yara_scanner.analyze_yara("anything.bin")
    assert r["status"] == "error"
    assert "timed out" in r["error"]
    assert r["findings"] == []

def test_cache_write_failure_does_not_break_scan(monkeypatch):
    monkeypatch.setattr(yara_scanner, "_rules", None)
    monkeypatch.setattr(yara_scanner, "_cache_is_fresh", lambda: False)
    monkeypatch.setattr(yara_scanner.os, "replace",
                        mock.Mock(side_effect=PermissionError("read-only")))
    rules = yara_scanner.get_rules()
    assert rules is not None


def test_missing_rules_file_is_error_not_crash(monkeypatch, tmp_path):
    monkeypatch.setattr(yara_scanner, "_rules", None)
    monkeypatch.setattr(yara_scanner, "RULES_PATH", str(tmp_path / "nope.yar"))
    monkeypatch.setattr(yara_scanner, "COMPILED_PATH", str(tmp_path / "nope.yarc"))
    target = tmp_path / "x.bin"
    target.write_bytes(b"hello")
    r = yara_scanner.analyze_yara(target)
    assert r["status"] == "error"
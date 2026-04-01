"""Tests for the Finding and ScanResult models."""

from jupysec.core.finding import Finding, ScanResult, Severity


def test_finding_sort_key():
    critical = Finding(check_id="a", severity=Severity.CRITICAL, title="", description="")
    low = Finding(check_id="b", severity=Severity.LOW, title="", description="")
    assert critical.sort_key() < low.sort_key()


def test_scan_result_summary():
    result = ScanResult()
    result.findings = [
        Finding(check_id="a", severity=Severity.CRITICAL, title="", description=""),
        Finding(check_id="b", severity=Severity.HIGH, title="", description=""),
        Finding(check_id="c", severity=Severity.CRITICAL, title="", description=""),
    ]
    assert result.summary == {"critical": 2, "high": 1}


def test_scan_result_json_roundtrip():
    result = ScanResult(target_url="https://example.com", mode="external")
    result.findings.append(
        Finding(check_id="test/check", severity=Severity.LOW, title="Test", description="Desc")
    )
    json_str = result.model_dump_json()
    restored = ScanResult.model_validate_json(json_str)
    assert restored.target_url == "https://example.com"
    assert len(restored.findings) == 1
    assert restored.findings[0].check_id == "test/check"

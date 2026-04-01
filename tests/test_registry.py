"""Tests for the check registry auto-discovery."""

from jupysec.core.registry import discover_checks


def test_discovers_checks():
    checks = discover_checks()
    assert len(checks) > 20
    ids = [c.id for c in checks]
    assert "auth/token-required" in ids
    assert "config/cookie-secret" in ids
    assert "supply/cve-check" in ids


def test_no_duplicate_ids():
    checks = discover_checks()
    ids = [c.id for c in checks]
    assert len(ids) == len(set(ids))


def test_all_checks_have_metadata():
    checks = discover_checks()
    for c in checks:
        assert c.id, f"Check {c} has no id"
        assert c.title, f"Check {c.id} has no title"
        assert c.severity, f"Check {c.id} has no severity"
        assert c.category, f"Check {c.id} has no category"
        assert c.mode in ("external", "internal", "both"), f"Check {c.id} has invalid mode: {c.mode}"

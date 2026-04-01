"""Tests for the CVE knowledge base."""

from jupysec.knowledge.cve_db import JUPYTER_CVES


def test_cve_db_not_empty():
    assert len(JUPYTER_CVES) > 5


def test_cve_affects_old_version():
    hub_cves = [c for c in JUPYTER_CVES if c.package == "jupyterhub"]
    assert len(hub_cves) > 0
    cve = hub_cves[0]
    assert cve.affects("3.0.0")


def test_cve_does_not_affect_new_version():
    hub_cves = [c for c in JUPYTER_CVES if c.package == "jupyterhub"]
    cve = hub_cves[0]
    assert not cve.affects("99.0.0")


def test_cve_handles_invalid_version():
    hub_cves = [c for c in JUPYTER_CVES if c.package == "jupyterhub"]
    cve = hub_cves[0]
    assert not cve.affects("not-a-version")

"""Tests for the benchmark framework."""

from jupysec.knowledge.benchmark import JUPYTERHUB_BENCHMARK, get_benchmark_results


def test_benchmark_not_empty():
    assert len(JUPYTERHUB_BENCHMARK) > 20


def test_benchmark_all_pass():
    checks_run = {"auth/token-required", "config/cookie-secret", "network/tls-config"}
    findings = set()  # No findings = all pass
    results = get_benchmark_results(findings, checks_run)
    passed = [r for r in results if r["status"] == "pass"]
    assert len(passed) > 0


def test_benchmark_fail():
    checks_run = {"auth/token-required", "api/endpoint-enum"}
    findings = {"auth/token-required"}
    results = get_benchmark_results(findings, checks_run)
    jhb_1_1 = [r for r in results if r["id"] == "JHB-1.1"]
    assert len(jhb_1_1) == 1
    assert jhb_1_1[0]["status"] == "fail"


def test_benchmark_skip():
    results = get_benchmark_results(set(), set())  # Nothing run
    assert all(r["status"] == "skip" for r in results)

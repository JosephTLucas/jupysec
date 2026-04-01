"""Scan orchestration engine."""

from __future__ import annotations

import asyncio
import traceback
from datetime import datetime, timezone

from rich.console import Console

from jupysec.checks.base import BaseCheck
from jupysec.core.finding import Finding, ScanResult, Severity
from jupysec.core.profile import ScanProfile
from jupysec.core.registry import discover_checks
from jupysec.core.target import Target

console = Console(stderr=True)


async def _run_check_safe(check: BaseCheck, target: Target) -> tuple[str, list[Finding], bool]:
    """Run a single check, catching exceptions to avoid aborting the scan."""
    try:
        findings = await check.run(target)
        return check.id, findings, False
    except Exception as exc:
        tb = traceback.format_exception_only(type(exc), exc)
        error_finding = Finding(
            check_id=check.id,
            severity=Severity.INFO,
            title=f"Check error: {check.id}",
            description=f"Check raised an exception: {''.join(tb).strip()}",
            evidence=traceback.format_exc(),
            target_component="scanner",
        )
        return check.id, [error_finding], True


async def run_scan(target: Target, profile: ScanProfile) -> ScanResult:
    """Execute all applicable checks against the target."""
    all_checks = discover_checks()

    applicable = [
        c
        for c in all_checks
        if profile.should_run_check(c.id, c.mode) and c.prerequisites_met(target)
    ]

    console.print(f"[bold]jupysec[/bold] — discovered {len(all_checks)} checks, "
                  f"running {len(applicable)} for mode={profile.mode.value}")

    result = ScanResult(
        target_url=target.url,
        config_path=str(target.config_path) if target.config_path else None,
        mode=profile.mode.value,
    )

    semaphore = asyncio.Semaphore(profile.concurrency)

    async def bounded(check: BaseCheck) -> tuple[str, list[Finding], bool]:
        async with semaphore:
            return await _run_check_safe(check, target)

    tasks = [bounded(c) for c in applicable]
    outcomes = await asyncio.gather(*tasks)

    for check_id, findings, errored in outcomes:
        result.checks_run += 1
        if errored:
            result.checks_errored += 1
        elif findings:
            result.checks_failed += 1
        else:
            result.checks_passed += 1
        result.findings.extend(findings)

    result.findings.sort(key=lambda f: f.sort_key())
    result.completed_at = datetime.now(timezone.utc)
    return result

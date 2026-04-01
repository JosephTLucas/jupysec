"""CVE checking against installed Jupyter component versions."""

from __future__ import annotations

import httpx

from jupysec.checks.base import BaseCheck
from jupysec.core.finding import Category, Finding, Severity
from jupysec.core.target import Target
from jupysec.knowledge.cve_db import JUPYTER_CVES
from jupysec.utils.http import client_for


SEVERITY_MAP = {
    "critical": Severity.CRITICAL,
    "high": Severity.HIGH,
    "medium": Severity.MEDIUM,
    "low": Severity.LOW,
}


class CVECheck(BaseCheck):
    id = "supply/cve-check"
    title = "Installed versions checked against known CVEs"
    severity = Severity.HIGH
    category = Category.SUPPLY_CHAIN
    mode = "both"
    references = [
        "https://www.opencve.io/cve?vendor=jupyterhub",
    ]

    async def run(self, target: Target) -> list[Finding]:
        findings: list[Finding] = []
        detected_versions: dict[str, str] = {}

        # External: try to detect JupyterHub version from API
        if target.has_external:
            async with client_for(target) as client:
                try:
                    resp = await client.get("/hub/api/")
                    if resp.status_code == 200:
                        data = resp.json()
                        ver = data.get("version", "")
                        if ver:
                            detected_versions["jupyterhub"] = ver
                except (httpx.HTTPError, ValueError):
                    pass

                # Try Jupyter Server version
                try:
                    resp = await client.get("/api")
                    if resp.status_code == 200:
                        data = resp.json()
                        ver = data.get("version", "")
                        if ver:
                            detected_versions["jupyter-server"] = ver
                except (httpx.HTTPError, ValueError):
                    pass

        # Internal: check installed packages via Python
        if target.has_internal:
            try:
                from importlib.metadata import version as pkg_version, PackageNotFoundError

                for pkg in [
                    "jupyterhub", "jupyter-server", "jupyter-server-proxy",
                    "jupyter-core", "nbconvert",
                    "jupyterhub-firstuseauthenticator",
                ]:
                    try:
                        detected_versions.setdefault(pkg, pkg_version(pkg))
                    except PackageNotFoundError:
                        pass
            except ImportError:
                pass

        for pkg_name, pkg_ver in detected_versions.items():
            for cve in JUPYTER_CVES:
                if cve.package != pkg_name:
                    continue
                if cve.affects(pkg_ver):
                    findings.append(Finding(
                        check_id=self.id,
                        severity=SEVERITY_MAP.get(cve.severity, Severity.MEDIUM),
                        title=f"{cve.cve_id}: {cve.package} {pkg_ver}",
                        description=f"{cve.description} Installed: {pkg_ver}, fixed in: {cve.fixed_in}.",
                        evidence=f"{cve.package}=={pkg_ver} (affected: {cve.affected})",
                        remediation=f"Upgrade {cve.package} to >= {cve.fixed_in}.",
                        cwe=None,
                        references=[cve.url],
                        target_component="hub",
                        benchmark_id=cve.cve_id,
                    ))

        return findings

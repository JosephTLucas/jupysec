"""API information disclosure checks."""

from __future__ import annotations

import httpx

from jupysec.checks.base import BaseCheck
from jupysec.core.finding import Category, Finding, Severity
from jupysec.core.target import Target
from jupysec.utils.http import client_for


class InfoDisclosureCheck(BaseCheck):
    id = "api/info-disclosure"
    title = "Hub API does not leak sensitive info"
    severity = Severity.MEDIUM
    category = Category.API
    mode = "external"
    cwe = "CWE-200"
    references = [
        "https://jupyterhub.readthedocs.io/en/stable/reference/rest-api.html",
    ]

    async def run(self, target: Target) -> list[Finding]:
        findings: list[Finding] = []

        async with client_for(target) as client:
            try:
                resp = await client.get("/hub/api/")
            except httpx.HTTPError:
                return findings

            if resp.status_code == 200:
                try:
                    data = resp.json()
                    version = data.get("version", "")
                    if version:
                        findings.append(Finding(
                            check_id=self.id,
                            severity=Severity.LOW,
                            title="JupyterHub version disclosed via API",
                            description=(
                                f"The /hub/api/ endpoint reveals the JupyterHub version ({version}). "
                                "This helps attackers identify known vulnerabilities."
                            ),
                            evidence=f"version: {version}",
                            remediation=(
                                "Consider placing the Hub API behind a reverse proxy that "
                                "strips version info from unauthenticated endpoints."
                            ),
                            cwe=self.cwe,
                            references=self.references,
                            target_component="hub",
                        ))
                except Exception:
                    pass

        return findings


class VersionHeadersCheck(BaseCheck):
    id = "api/version-headers"
    title = "Server version not leaked in headers"
    severity = Severity.LOW
    category = Category.API
    mode = "external"
    cwe = "CWE-200"
    references = [
        "https://owasp.org/www-project-web-security-testing-guide/latest/4-Web_Application_Security_Testing/01-Information_Gathering/02-Fingerprinting_Web_Server",
    ]

    LEAKY_HEADERS = ["server", "x-powered-by", "x-jupyterhub-version"]

    async def run(self, target: Target) -> list[Finding]:
        findings: list[Finding] = []

        async with httpx.AsyncClient(
            base_url=target.base_url,
            verify=target.verify_ssl,
            timeout=target.timeout,
            follow_redirects=True,
        ) as client:
            try:
                resp = await client.get("/hub/login")
            except httpx.HTTPError:
                return findings

            for hdr in self.LEAKY_HEADERS:
                val = resp.headers.get(hdr, "")
                if val and any(char.isdigit() for char in val):
                    findings.append(Finding(
                        check_id=self.id,
                        severity=Severity.LOW,
                        title=f"Version info in '{hdr}' header",
                        description=(
                            f"The response header '{hdr}: {val}' reveals software version "
                            "information that aids attacker reconnaissance."
                        ),
                        evidence=f"{hdr}: {val}",
                        remediation=f"Configure your reverse proxy to strip or genericize the '{hdr}' header.",
                        cwe=self.cwe,
                        references=self.references,
                        target_component="proxy",
                    ))

        return findings

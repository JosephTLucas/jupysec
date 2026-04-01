"""API endpoint enumeration and permission probing."""

from __future__ import annotations

import httpx

from jupysec.checks.base import BaseCheck
from jupysec.core.finding import Category, Finding, Severity
from jupysec.core.target import Target
from jupysec.knowledge.api_specs import HUB_API_ENDPOINTS
from jupysec.utils.http import client_for


class EndpointEnumerationCheck(BaseCheck):
    id = "api/endpoint-enum"
    title = "API endpoint accessibility audit"
    severity = Severity.MEDIUM
    category = Category.API
    mode = "external"
    references = [
        "https://jupyterhub.readthedocs.io/en/stable/reference/rest-api.html",
    ]

    async def run(self, target: Target) -> list[Finding]:
        findings: list[Finding] = []
        accessible: list[str] = []

        async with httpx.AsyncClient(
            base_url=target.base_url,
            verify=target.verify_ssl,
            timeout=target.timeout,
            follow_redirects=True,
        ) as anon_client:
            for ep in HUB_API_ENDPOINTS:
                path = ep["path"].replace("{name}", "_probe_").replace("{token}", "_probe_")
                try:
                    resp = await anon_client.request(ep["method"], path)
                    if resp.status_code < 400:
                        accessible.append(f"{ep['method']} {ep['path']} ({ep['desc']})")
                except httpx.HTTPError:
                    continue

        if accessible:
            findings.append(Finding(
                check_id=self.id,
                severity=Severity.HIGH,
                title=f"{len(accessible)} API endpoint(s) accessible without auth",
                description=(
                    "The following Hub API endpoints returned success responses "
                    "without authentication credentials:\n"
                    + "\n".join(f"  - {e}" for e in accessible)
                ),
                evidence="\n".join(accessible),
                remediation=(
                    "Ensure all API endpoints require authentication. Check proxy "
                    "configuration and JupyterHub RBAC settings."
                ),
                references=self.references,
                target_component="hub",
            ))

        return findings


class PermissionProbeCheck(BaseCheck):
    id = "api/permission-probe"
    title = "API permissions are properly scoped"
    severity = Severity.HIGH
    category = Category.API
    mode = "external"
    cwe = "CWE-862"
    references = [
        "https://jupyterhub.readthedocs.io/en/stable/rbac/index.html",
    ]

    async def run(self, target: Target) -> list[Finding]:
        if not target.token:
            return []

        findings: list[Finding] = []
        admin_endpoints = [
            ep for ep in HUB_API_ENDPOINTS
            if "admin" in ep.get("scope", "") or ep["path"] == "/hub/api/proxy"
        ]

        async with client_for(target) as client:
            for ep in admin_endpoints:
                path = ep["path"].replace("{name}", "_probe_").replace("{token}", "_probe_")
                try:
                    resp = await client.request(ep["method"], path)
                    if resp.status_code < 400:
                        findings.append(Finding(
                            check_id=self.id,
                            severity=Severity.HIGH,
                            title=f"Token has access to admin endpoint: {ep['path']}",
                            description=(
                                f"The provided token can access {ep['method']} {ep['path']} "
                                f"(requires scope: {ep['scope']}). Verify this token's "
                                "scopes follow least-privilege."
                            ),
                            evidence=f"{ep['method']} {ep['path']} -> {resp.status_code}",
                            remediation=(
                                "Use scoped tokens with minimal permissions. Create tokens "
                                "via /hub/token with only the required scopes."
                            ),
                            cwe=self.cwe,
                            references=self.references,
                            target_component="hub",
                        ))
                except httpx.HTTPError:
                    continue

        return findings

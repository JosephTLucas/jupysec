"""Proxy route integrity checks."""

from __future__ import annotations

import httpx

from jupysec.checks.base import BaseCheck
from jupysec.core.finding import Category, Finding, Severity
from jupysec.core.target import Target
from jupysec.utils.http import client_for


class ProxyRoutesCheck(BaseCheck):
    id = "isolation/proxy-routes"
    title = "Proxy routes are not tampered with"
    severity = Severity.HIGH
    category = Category.ISOLATION
    mode = "external"
    cwe = "CWE-441"
    references = [
        "https://jupyterhub.readthedocs.io/en/stable/reference/rest-api.html",
    ]

    def prerequisites_met(self, target: Target) -> bool:
        return target.has_external and target.token is not None

    async def run(self, target: Target) -> list[Finding]:
        findings: list[Finding] = []

        async with client_for(target) as client:
            try:
                resp = await client.get("/hub/api/proxy")
            except httpx.HTTPError:
                return findings

            if resp.status_code != 200:
                return findings

            try:
                routes = resp.json()
            except ValueError:
                return findings

            if not isinstance(routes, dict):
                return findings

            # Check for suspicious route targets
            for route_path, route_info in routes.items():
                route_target = ""
                if isinstance(route_info, dict):
                    route_target = route_info.get("target", "")

                if not route_target:
                    continue

                # Flag routes pointing outside the expected internal network
                if any(suspicious in route_target.lower() for suspicious in [
                    "//0.0.0.0", "//[::]", "external", ".io:", ".com:",
                ]):
                    findings.append(Finding(
                        check_id=self.id,
                        severity=Severity.HIGH,
                        title=f"Suspicious proxy route: {route_path}",
                        description=(
                            f"Route '{route_path}' points to '{route_target}', "
                            "which may indicate route injection or misconfiguration."
                        ),
                        evidence=f"Route: {route_path} -> {route_target}",
                        remediation=(
                            "Audit proxy routes. Ensure only legitimate user servers "
                            "and Hub services are routed."
                        ),
                        cwe=self.cwe,
                        references=self.references,
                        target_component="proxy",
                    ))

        return findings


class AdminEscalationCheck(BaseCheck):
    id = "auth/admin-escalation"
    title = "Non-admin cannot escalate to admin"
    severity = Severity.CRITICAL
    category = Category.AUTH
    mode = "external"
    cwe = "CWE-269"
    references = [
        "https://nvd.nist.gov/vuln/detail/CVE-2024-41942",
        "https://jupyterhub.readthedocs.io/en/stable/rbac/index.html",
    ]

    def prerequisites_met(self, target: Target) -> bool:
        return target.has_external and target.token is not None

    async def run(self, target: Target) -> list[Finding]:
        findings: list[Finding] = []

        async with client_for(target) as client:
            # Check current user permissions
            try:
                user_resp = await client.get("/hub/api/user")
                if user_resp.status_code != 200:
                    return findings
                user_data = user_resp.json()
            except (httpx.HTTPError, ValueError):
                return findings

            is_admin = user_data.get("admin", False)
            if is_admin:
                return findings  # Already admin, not an escalation test

            # Try to PATCH self to become admin (CVE-2024-41942 pattern)
            username = user_data.get("name", "")
            if not username:
                return findings

            try:
                patch_resp = await client.patch(
                    f"/hub/api/users/{username}",
                    json={"admin": True},
                )

                if patch_resp.status_code == 200:
                    result_data = patch_resp.json()
                    if result_data.get("admin") is True:
                        findings.append(Finding(
                            check_id=self.id,
                            severity=Severity.CRITICAL,
                            title="Privilege escalation: non-admin can become admin",
                            description=(
                                f"User '{username}' was able to set admin=true via "
                                "PATCH /hub/api/users/{name}. This is the CVE-2024-41942 "
                                "vulnerability pattern."
                            ),
                            evidence=f"PATCH /hub/api/users/{username} with admin=true -> 200",
                            remediation=(
                                "Update JupyterHub to >= 4.1.6 or >= 5.1.0. "
                                "Review RBAC roles to ensure admin:users scope is "
                                "not granted to non-admin users."
                            ),
                            cwe=self.cwe,
                            references=self.references,
                            target_component="hub",
                        ))

                        # Attempt to revert
                        try:
                            await client.patch(
                                f"/hub/api/users/{username}",
                                json={"admin": False},
                            )
                        except httpx.HTTPError:
                            pass

            except httpx.HTTPError:
                pass

        return findings

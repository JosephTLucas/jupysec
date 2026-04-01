"""Cross-user network isolation testing."""

from __future__ import annotations

import httpx

from jupysec.checks.base import BaseCheck
from jupysec.core.finding import Category, Finding, Severity
from jupysec.core.target import Target
from jupysec.utils.http import client_for


class CrossUserNetworkCheck(BaseCheck):
    id = "isolation/cross-user"
    title = "Users cannot access other users' server APIs"
    severity = Severity.CRITICAL
    category = Category.ISOLATION
    mode = "external"
    cwe = "CWE-284"
    references = [
        "https://jupyterhub.readthedocs.io/en/stable/explanation/websecurity.html",
    ]

    def prerequisites_met(self, target: Target) -> bool:
        return target.has_external and target.token is not None

    async def run(self, target: Target) -> list[Finding]:
        findings: list[Finding] = []

        async with client_for(target) as client:
            # Identify current user
            try:
                user_resp = await client.get("/hub/api/user")
                if user_resp.status_code != 200:
                    return findings
                current_user = user_resp.json().get("name", "")
            except (httpx.HTTPError, ValueError):
                return findings

            # List other users with running servers
            try:
                users_resp = await client.get("/hub/api/users")
                if users_resp.status_code != 200:
                    return findings
                users = users_resp.json()
            except (httpx.HTTPError, ValueError):
                return findings

            for user in users:
                name = user.get("name", "")
                if name == current_user or not name:
                    continue
                if not user.get("server") and not user.get("servers"):
                    continue

                probe_paths = [
                    f"/user/{name}/api",
                    f"/user/{name}/api/contents",
                    f"/user/{name}/api/kernels",
                    f"/user/{name}/api/terminals",
                ]

                for path in probe_paths:
                    try:
                        resp = await client.get(path)
                    except httpx.HTTPError:
                        continue

                    if resp.status_code == 200:
                        findings.append(Finding(
                            check_id=self.id,
                            severity=Severity.CRITICAL,
                            title=f"Cross-user API access: {current_user} -> {name}",
                            description=(
                                f"User '{current_user}' can access {path} on user "
                                f"'{name}''s server (HTTP 200). This breaks user isolation "
                                "and may allow file access or code execution as another user."
                            ),
                            evidence=f"GET {path} -> 200",
                            remediation=(
                                "Verify JupyterHub RBAC configuration. Ensure users don't have "
                                "access:servers scope for other users. Consider per-user subdomains."
                            ),
                            cwe=self.cwe,
                            references=self.references,
                            target_component="proxy",
                        ))
                        break  # One path per user is sufficient

        return findings

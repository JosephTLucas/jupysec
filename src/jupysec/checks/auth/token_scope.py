"""Token scope analysis: what can a compromised notebook actually do?

JupyterHub injects JUPYTERHUB_API_TOKEN into every user server's environment.
This check determines the blast radius of a compromised notebook by testing
what the token can actually do -- not just which endpoints respond, but which
dangerous operations succeed.

This models the attacker who has achieved code execution in a notebook
(whether through a compromised user account, shared notebook with malicious
code, or supply chain attack on a pip package).
"""

from __future__ import annotations

import httpx

from jupysec.checks.base import BaseCheck
from jupysec.core.finding import Category, Finding, Severity
from jupysec.core.target import Target
from jupysec.utils.http import client_for


class TokenScopeAnalysisCheck(BaseCheck):
    id = "attack/token-blast-radius"
    title = "API token blast radius analysis"
    severity = Severity.HIGH
    category = Category.AUTH
    mode = "external"
    cwe = "CWE-269"
    references = [
        "https://jupyterhub.readthedocs.io/en/stable/rbac/index.html",
    ]

    def prerequisites_met(self, target: Target) -> bool:
        return target.has_external and target.token is not None

    async def run(self, target: Target) -> list[Finding]:
        findings: list[Finding] = []
        capabilities: list[str] = []

        async with client_for(target) as client:
            # What user are we?
            try:
                resp = await client.get("/hub/api/user")
                if resp.status_code != 200:
                    return findings
                user_data = resp.json()
                username = user_data.get("name", "")
                is_admin = user_data.get("admin", False)
            except (httpx.HTTPError, ValueError):
                return findings

            if is_admin:
                capabilities.append("ADMIN: token has full admin privileges")

            # Can we list all users? (information disclosure)
            try:
                resp = await client.get("/hub/api/users")
                if resp.status_code == 200:
                    users = resp.json()
                    capabilities.append(f"LIST_USERS: can enumerate all {len(users)} users")
            except httpx.HTTPError:
                pass

            # Can we create new API tokens? (persistence)
            try:
                resp = await client.post(
                    f"/hub/api/users/{username}/tokens",
                    json={"note": "jupysec-probe", "expires_in": 60},
                )
                if resp.status_code in (200, 201):
                    token_data = resp.json()
                    capabilities.append("CREATE_TOKENS: can create new API tokens (persistence)")
                    # Clean up the probe token
                    token_id = token_data.get("id", "")
                    if token_id:
                        try:
                            await client.delete(
                                f"/hub/api/users/{username}/tokens/{token_id}"
                            )
                        except httpx.HTTPError:
                            pass
            except httpx.HTTPError:
                pass

            # Can we start/stop other users' servers? (disruption + lateral movement)
            try:
                resp = await client.get("/hub/api/users")
                if resp.status_code == 200:
                    other_users = [
                        u for u in resp.json()
                        if u.get("name") != username
                    ]
                    if other_users:
                        probe_user = other_users[0]["name"]
                        # Don't actually start a server, just check if POST would be allowed
                        # by sending to a non-existent named server
                        resp = await client.post(
                            f"/hub/api/users/{probe_user}/servers/jupysec-probe",
                            json={},
                        )
                        if resp.status_code in (200, 201, 202):
                            capabilities.append(
                                f"START_OTHERS_SERVERS: can start servers for other users"
                            )
                            # Clean up
                            try:
                                await client.delete(
                                    f"/hub/api/users/{probe_user}/servers/jupysec-probe"
                                )
                            except httpx.HTTPError:
                                pass
            except httpx.HTTPError:
                pass

            # Can we read proxy routes? (network topology disclosure)
            try:
                resp = await client.get("/hub/api/proxy")
                if resp.status_code == 200:
                    routes = resp.json()
                    capabilities.append(
                        f"READ_PROXY: can see all {len(routes)} proxy routes (internal topology)"
                    )
            except httpx.HTTPError:
                pass

            # Can we access services? (lateral movement)
            try:
                resp = await client.get("/hub/api/services")
                if resp.status_code == 200:
                    services = resp.json()
                    if services:
                        capabilities.append(
                            f"READ_SERVICES: can enumerate {len(services)} Hub services"
                        )
            except httpx.HTTPError:
                pass

        if not capabilities:
            return findings

        severity = Severity.CRITICAL if is_admin or "START_OTHERS_SERVERS" in str(capabilities) else Severity.HIGH

        findings.append(Finding(
            check_id=self.id,
            severity=severity,
            title=f"Token for '{username}' has {len(capabilities)} exploitable capabilities",
            description=(
                "Analysis of what an attacker can do with this API token "
                "(e.g., from a compromised notebook where JUPYTERHUB_API_TOKEN is in env):\n"
                + "\n".join(f"  - {c}" for c in capabilities)
            ),
            evidence="\n".join(capabilities),
            remediation=(
                "Minimize token scopes. Use JupyterHub RBAC to create roles with "
                "only the necessary scopes. The default user token should not be able "
                "to list users, read proxy routes, or start other users' servers. "
                "Set c.JupyterHub.load_roles to define restricted roles."
            ),
            cwe=self.cwe,
            references=self.references,
            target_component="hub",
        ))

        return findings


class EnvironmentTokenLeakCheck(BaseCheck):
    """Check if the user's kernel environment leaks sensitive tokens.

    When an attacker gets code execution in a notebook, the first thing they
    do is `import os; os.environ` to find credentials.
    """

    id = "attack/env-token-leak"
    title = "Sensitive tokens accessible in kernel environment"
    severity = Severity.MEDIUM
    category = Category.AUTH
    mode = "external"
    cwe = "CWE-522"
    references = [
        "https://jupyterhub.readthedocs.io/en/stable/reference/spawners.html",
    ]

    def prerequisites_met(self, target: Target) -> bool:
        return target.has_external and target.token is not None

    async def run(self, target: Target) -> list[Finding]:
        findings: list[Finding] = []

        # Use the SSRF check's kernel execution infrastructure
        from jupysec.checks.isolation.ssrf import CloudMetadataSSRFCheck

        ssrf_check = CloudMetadataSSRFCheck()
        kernel_id = await ssrf_check._get_or_start_kernel(target)
        if not kernel_id:
            return findings

        code = (
            "import os\n"
            "sensitive_keys = [k for k in os.environ if any(\n"
            "    s in k.upper() for s in ['TOKEN', 'SECRET', 'PASSWORD', 'KEY', 'CREDENTIAL', 'API_KEY']\n"
            ")]\n"
            "for k in sensitive_keys:\n"
            "    v = os.environ[k]\n"
            "    print(f'ENV_FOUND:{k}={v[:8]}...' if len(v) > 8 else f'ENV_FOUND:{k}={v}')\n"
            "if not sensitive_keys:\n"
            "    print('ENV_CLEAN')\n"
        )

        result = await ssrf_check._execute_in_kernel(target, kernel_id, code)
        if not result:
            return findings

        found_vars = [
            line.replace("ENV_FOUND:", "")
            for line in result.splitlines()
            if line.startswith("ENV_FOUND:")
        ]

        if found_vars:
            findings.append(Finding(
                check_id=self.id,
                severity=Severity.MEDIUM,
                title=f"{len(found_vars)} sensitive env var(s) in kernel environment",
                description=(
                    "The following environment variables containing tokens/secrets are "
                    "accessible to code running in user notebooks. An attacker with "
                    "notebook access can harvest these:\n"
                    + "\n".join(f"  - {v}" for v in found_vars)
                ),
                evidence="\n".join(found_vars),
                remediation=(
                    "JUPYTERHUB_API_TOKEN is unavoidable, but minimize its scopes. "
                    "Avoid passing additional secrets via c.Spawner.environment. "
                    "Use mounted secret files instead of env vars where possible."
                ),
                cwe=self.cwe,
                references=self.references,
                target_component="spawner",
            ))

        return findings

"""WebSocket kernel authentication checks (CVE-2024-28179 pattern)."""

from __future__ import annotations

import httpx

from jupysec.checks.base import BaseCheck
from jupysec.core.finding import Category, Finding, Severity
from jupysec.core.target import Target
from jupysec.utils.http import client_for
from jupysec.utils.websocket import try_ws_connect, ws_url_for


class KernelAuthCheck(BaseCheck):
    id = "ws/kernel-auth"
    title = "WebSocket kernel endpoints require authentication"
    severity = Severity.CRITICAL
    category = Category.WEBSOCKET
    mode = "external"
    cwe = "CWE-306"
    references = [
        "https://nvd.nist.gov/vuln/detail/CVE-2024-28179",
        "https://jupyter-server.readthedocs.io/en/latest/developers/websocket-protocols.html",
    ]

    async def run(self, target: Target) -> list[Finding]:
        findings: list[Finding] = []

        # First, discover any running kernels via the REST API (needs auth).
        # If no token, we'll try known common paths with fabricated kernel IDs.
        kernel_ws_paths: list[str] = []

        if target.token:
            async with client_for(target) as client:
                try:
                    resp = await client.get("/hub/api/users")
                    if resp.status_code == 200:
                        users = resp.json()
                        for user in users[:3]:  # Probe first few users
                            name = user.get("name", "")
                            if name and user.get("server"):
                                kernel_ws_paths.append(
                                    f"/user/{name}/api/kernels/fake-kernel-id/channels"
                                )
                except httpx.HTTPError:
                    pass

        # Always try the base server path pattern
        kernel_ws_paths.extend([
            "/api/kernels/00000000-0000-0000-0000-000000000000/channels",
            "/terminals/websocket/1",
        ])

        for path in kernel_ws_paths:
            ws_url = ws_url_for(target.base_url, path)

            # Try WITHOUT auth
            connected, detail = await try_ws_connect(
                ws_url, token=None, verify_ssl=target.verify_ssl, timeout=10.0,
            )

            if connected:
                findings.append(Finding(
                    check_id=self.id,
                    severity=Severity.CRITICAL,
                    title=f"Unauthenticated WebSocket access: {path}",
                    description=(
                        f"The WebSocket endpoint {path} accepted a connection without "
                        "any authentication. This could allow unauthenticated remote "
                        "code execution via kernel protocol messages."
                    ),
                    evidence=f"ws connect to {ws_url} (no auth): {detail}",
                    remediation=(
                        "Ensure jupyter-server-proxy >= 3.2.4 / 4.2.0. "
                        "Verify that WebSocket endpoints require authentication in "
                        "your Jupyter Server and proxy configuration."
                    ),
                    cwe=self.cwe,
                    references=self.references,
                    target_component="user-server",
                ))

        return findings


class KernelIsolationCheck(BaseCheck):
    id = "ws/kernel-isolation"
    title = "Users cannot access other users' kernel WebSockets"
    severity = Severity.CRITICAL
    category = Category.WEBSOCKET
    mode = "external"
    cwe = "CWE-284"
    references = [
        "https://jupyterhub.readthedocs.io/en/stable/explanation/websecurity.html",
    ]

    def prerequisites_met(self, target: Target) -> bool:
        return target.has_external and target.token is not None

    async def run(self, target: Target) -> list[Finding]:
        """Try to connect to another user's kernel WS path using our token."""
        findings: list[Finding] = []

        async with client_for(target) as client:
            try:
                resp = await client.get("/hub/api/users")
                if resp.status_code != 200:
                    return findings
                users = resp.json()
            except (httpx.HTTPError, ValueError):
                return findings

        # Find current user and another user with a running server
        current_resp = None
        async with client_for(target) as client:
            try:
                current_resp = await client.get("/hub/api/user")
            except httpx.HTTPError:
                return findings

        if not current_resp or current_resp.status_code != 200:
            return findings

        try:
            current_user = current_resp.json().get("name", "")
        except ValueError:
            return findings

        for user in users:
            name = user.get("name", "")
            if name == current_user or not name:
                continue
            if not user.get("server") and not user.get("servers"):
                continue

            path = f"/user/{name}/api/kernels/00000000-0000-0000-0000-000000000000/channels"
            ws_url = ws_url_for(target.base_url, path)

            connected, detail = await try_ws_connect(
                ws_url, token=target.token, verify_ssl=target.verify_ssl, timeout=10.0,
            )

            if connected:
                findings.append(Finding(
                    check_id=self.id,
                    severity=Severity.CRITICAL,
                    title=f"Cross-user WebSocket access to {name}'s server",
                    description=(
                        f"Token for user '{current_user}' was able to open a WebSocket "
                        f"connection to user '{name}''s kernel endpoint. This breaks "
                        "user isolation and may allow cross-user code execution."
                    ),
                    evidence=f"Connected to {ws_url} with {current_user}'s token",
                    remediation=(
                        "Verify JupyterHub proxy and RBAC configuration. "
                        "Ensure per-user subdomains or strict path-based isolation."
                    ),
                    cwe=self.cwe,
                    references=self.references,
                    target_component="proxy",
                ))
                break  # One finding is sufficient

        return findings

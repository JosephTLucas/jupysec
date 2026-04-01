"""XSRF token enforcement check."""

from __future__ import annotations

import httpx

from jupysec.checks.base import BaseCheck
from jupysec.core.finding import Category, Finding, Severity
from jupysec.core.target import Target
from jupysec.utils.http import client_for


class XSRFEnforcementCheck(BaseCheck):
    id = "api/xsrf-enforcement"
    title = "State-changing requests require XSRF token"
    severity = Severity.HIGH
    category = Category.API
    mode = "external"
    cwe = "CWE-352"
    references = [
        "https://jupyterhub.readthedocs.io/en/stable/reference/rest-api.html",
    ]

    async def run(self, target: Target) -> list[Finding]:
        if not target.token:
            return []

        findings: list[Finding] = []

        # Try a state-changing request without XSRF token
        async with httpx.AsyncClient(
            base_url=target.base_url,
            headers={"Authorization": f"token {target.token}"},
            verify=target.verify_ssl,
            timeout=target.timeout,
            follow_redirects=True,
        ) as client:
            test_endpoints = [
                ("POST", "/hub/api/users/_xsrf_probe_/tokens"),
                ("DELETE", "/hub/api/users/_xsrf_probe_/server"),
            ]

            for method, path in test_endpoints:
                try:
                    resp = await client.request(
                        method, path,
                        headers={"Content-Type": "application/json"},
                        content="{}",
                    )
                except httpx.HTTPError:
                    continue

                # 403 with "XSRF" in body means enforcement is working.
                # If we get something other than 403 and it's not a 404 (user not found),
                # XSRF might not be enforced.
                if resp.status_code == 403:
                    body = resp.text.lower()
                    if "xsrf" in body or "csrf" in body:
                        continue  # Good: XSRF is enforced

                # API token requests bypass XSRF by design in JupyterHub,
                # so 404 (user not found) or 401 are normal. Only flag if we
                # get a 200/201 on a truly state-changing endpoint.
                if resp.status_code in (200, 201):
                    findings.append(Finding(
                        check_id=self.id,
                        severity=Severity.HIGH,
                        title=f"State-changing endpoint accepts request without XSRF token",
                        description=(
                            f"{method} {path} succeeded (HTTP {resp.status_code}) without "
                            "an XSRF token. This may enable cross-site request forgery."
                        ),
                        evidence=f"{method} {path} -> {resp.status_code} (no _xsrf cookie/header)",
                        remediation="Ensure c.JupyterHub.cookie_options includes XSRF protection.",
                        cwe=self.cwe,
                        references=self.references,
                        target_component="hub",
                    ))

        return findings

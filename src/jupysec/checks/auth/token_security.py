"""Check that the Hub API requires authentication."""

from __future__ import annotations

import httpx

from jupysec.checks.base import BaseCheck
from jupysec.core.finding import Category, Finding, Severity
from jupysec.core.target import Target


class TokenRequiredCheck(BaseCheck):
    id = "auth/token-required"
    title = "Hub API requires authentication"
    severity = Severity.CRITICAL
    category = Category.AUTH
    mode = "external"
    cwe = "CWE-306"
    references = [
        "https://jupyterhub.readthedocs.io/en/stable/tutorial/getting-started/security-basics.html",
    ]

    async def run(self, target: Target) -> list[Finding]:
        findings: list[Finding] = []
        probe_paths = [
            "/hub/api/",
            "/hub/api/users",
            "/hub/api/proxy",
        ]

        async with httpx.AsyncClient(
            base_url=target.base_url,
            verify=target.verify_ssl,
            timeout=target.timeout,
            follow_redirects=True,
        ) as client:
            for path in probe_paths:
                try:
                    resp = await client.get(path)
                except httpx.HTTPError:
                    continue

                if resp.status_code == 200:
                    findings.append(Finding(
                        check_id=self.id,
                        severity=Severity.CRITICAL,
                        title=f"Unauthenticated access to {path}",
                        description=(
                            f"The endpoint {path} returned HTTP 200 without any "
                            "authentication credentials. An attacker with network "
                            "access can read sensitive Hub data."
                        ),
                        evidence=f"GET {path} -> {resp.status_code}",
                        remediation=(
                            "Ensure JupyterHub is configured to require authentication. "
                            "Check that the proxy is forwarding auth headers correctly."
                        ),
                        cwe=self.cwe,
                        references=self.references,
                        target_component="hub",
                    ))

        return findings


class CookieFlagsCheck(BaseCheck):
    id = "auth/cookie-flags"
    title = "Session cookies have security flags"
    severity = Severity.MEDIUM
    category = Category.AUTH
    mode = "external"
    cwe = "CWE-614"
    references = [
        "https://owasp.org/www-community/controls/SecureCookieAttribute",
    ]

    async def run(self, target: Target) -> list[Finding]:
        findings: list[Finding] = []

        async with httpx.AsyncClient(
            base_url=target.base_url,
            verify=target.verify_ssl,
            timeout=target.timeout,
            follow_redirects=False,
        ) as client:
            try:
                resp = await client.get("/hub/login")
            except httpx.HTTPError:
                return findings

            for cookie in resp.cookies.jar:
                issues = []
                if not cookie.secure:
                    issues.append("missing Secure flag")
                if cookie.has_nonstandard_attr("httponly") is False and "httponly" not in str(cookie).lower():
                    issues.append("missing HttpOnly flag")
                samesite_val = cookie.get_nonstandard_attr("samesite") or ""
                if not samesite_val:
                    issues.append("missing SameSite attribute")

                if issues:
                    findings.append(Finding(
                        check_id=self.id,
                        severity=Severity.MEDIUM,
                        title=f"Cookie '{cookie.name}' {', '.join(issues)}",
                        description=(
                            f"The cookie '{cookie.name}' is missing security attributes: "
                            f"{', '.join(issues)}. This may allow session hijacking or CSRF."
                        ),
                        evidence=f"Set-Cookie: {cookie.name}=...; {cookie}",
                        remediation=(
                            "Configure JupyterHub to set Secure, HttpOnly, and "
                            "SameSite=Lax on session cookies. If behind a TLS-terminating "
                            "proxy, set c.JupyterHub.cookie_options = {'SameSite': 'Lax', 'Secure': True}."
                        ),
                        cwe=self.cwe,
                        references=self.references,
                        target_component="hub",
                    ))

        return findings

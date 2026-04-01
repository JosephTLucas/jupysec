"""CORS policy assessment."""

from __future__ import annotations

import httpx

from jupysec.checks.base import BaseCheck
from jupysec.core.finding import Category, Finding, Severity
from jupysec.core.target import Target


class CORSPolicyCheck(BaseCheck):
    id = "network/cors-policy"
    title = "CORS policy is restrictive"
    severity = Severity.HIGH
    category = Category.NETWORK
    mode = "external"
    cwe = "CWE-942"
    references = [
        "https://owasp.org/www-community/attacks/CORS_OriginHeaderScrutiny",
    ]

    async def run(self, target: Target) -> list[Finding]:
        findings: list[Finding] = []
        probe_paths = ["/hub/api/", "/hub/login"]

        async with httpx.AsyncClient(
            base_url=target.base_url,
            verify=target.verify_ssl,
            timeout=target.timeout,
            follow_redirects=True,
        ) as client:
            for path in probe_paths:
                evil_origin = "https://evil.attacker.example"
                try:
                    resp = await client.options(
                        path,
                        headers={
                            "Origin": evil_origin,
                            "Access-Control-Request-Method": "GET",
                        },
                    )
                except httpx.HTTPError:
                    continue

                acao = resp.headers.get("access-control-allow-origin", "")

                if acao == "*":
                    findings.append(Finding(
                        check_id=self.id,
                        severity=Severity.HIGH,
                        title=f"Wildcard CORS on {path}",
                        description=(
                            f"The endpoint {path} returns Access-Control-Allow-Origin: * "
                            "which allows any website to make cross-origin requests to the Hub API."
                        ),
                        evidence=f"Access-Control-Allow-Origin: {acao}",
                        remediation=(
                            "Set a restrictive Access-Control-Allow-Origin that matches "
                            "only the Hub's own origin."
                        ),
                        cwe=self.cwe,
                        references=self.references,
                        target_component="hub",
                    ))
                elif acao == evil_origin:
                    findings.append(Finding(
                        check_id=self.id,
                        severity=Severity.HIGH,
                        title=f"CORS reflects arbitrary origin on {path}",
                        description=(
                            f"The endpoint {path} reflected the attacker-controlled Origin "
                            f"'{evil_origin}' in Access-Control-Allow-Origin. This effectively "
                            "disables the same-origin policy."
                        ),
                        evidence=f"Sent Origin: {evil_origin}, got ACAO: {acao}",
                        remediation="Fix the CORS configuration to whitelist only trusted origins.",
                        cwe=self.cwe,
                        references=self.references,
                        target_component="hub",
                    ))

                acac = resp.headers.get("access-control-allow-credentials", "").lower()
                if acac == "true" and acao in ("*", evil_origin):
                    findings.append(Finding(
                        check_id=self.id,
                        severity=Severity.CRITICAL,
                        title=f"CORS allows credentialed requests from any origin on {path}",
                        description=(
                            "The combination of a permissive Access-Control-Allow-Origin and "
                            "Access-Control-Allow-Credentials: true allows an attacker's site "
                            "to make authenticated cross-origin requests."
                        ),
                        evidence=f"ACAO: {acao}, ACAC: true",
                        remediation="Never combine Allow-Credentials: true with a wildcard or reflected origin.",
                        cwe=self.cwe,
                        references=self.references,
                        target_component="hub",
                    ))

        return findings


class CSPPolicyCheck(BaseCheck):
    id = "network/csp-policy"
    title = "Content-Security-Policy header present"
    severity = Severity.MEDIUM
    category = Category.NETWORK
    mode = "external"
    cwe = "CWE-1021"
    references = [
        "https://developer.mozilla.org/en-US/docs/Web/HTTP/CSP",
    ]

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

            csp = resp.headers.get("content-security-policy", "")
            if not csp:
                findings.append(Finding(
                    check_id=self.id,
                    severity=Severity.MEDIUM,
                    title="Missing Content-Security-Policy header",
                    description=(
                        "No CSP header was found on the Hub login page. "
                        "CSP helps mitigate XSS and data injection attacks."
                    ),
                    evidence=f"Response headers: {dict(resp.headers)}",
                    remediation=(
                        "Add a Content-Security-Policy header. A reasonable starting point: "
                        "default-src 'self'; script-src 'self'; style-src 'self' 'unsafe-inline'"
                    ),
                    cwe=self.cwe,
                    references=self.references,
                    target_component="hub",
                ))
            else:
                if "'unsafe-inline'" in csp and "'unsafe-eval'" in csp:
                    findings.append(Finding(
                        check_id=self.id,
                        severity=Severity.LOW,
                        title="CSP allows unsafe-inline and unsafe-eval",
                        description="The CSP includes both 'unsafe-inline' and 'unsafe-eval', significantly weakening XSS protection.",
                        evidence=f"CSP: {csp}",
                        remediation="Remove 'unsafe-eval' and replace 'unsafe-inline' with nonce or hash-based directives.",
                        cwe=self.cwe,
                        references=self.references,
                        target_component="hub",
                    ))

        return findings

"""Authenticator configuration security audit."""

from __future__ import annotations

from jupysec.checks.base import BaseCheck
from jupysec.core.finding import Category, Finding, Severity
from jupysec.core.target import Target
from jupysec.utils.config_parser import parse_config

INSECURE_AUTHENTICATORS = {
    "DummyAuthenticator": "Accepts any username/password combination.",
    "NullAuthenticator": "Requires no authentication at all.",
}

WEAK_AUTHENTICATORS = {
    "PAMAuthenticator": (
        "PAM authenticator uses system passwords. Ensure password policies "
        "are enforced at the OS level."
    ),
    "FirstUseAuthenticator": (
        "FirstUseAuthenticator lets anyone claim a username on first login. "
        "CVE-2021-41194: accounts can be taken over if create_users=True."
    ),
}


class AuthenticatorTypeCheck(BaseCheck):
    id = "config/authenticator-type"
    title = "Authenticator is not insecure"
    severity = Severity.CRITICAL
    category = Category.CONFIG
    mode = "internal"
    cwe = "CWE-287"
    references = [
        "https://jupyterhub.readthedocs.io/en/stable/reference/authenticators.html",
    ]

    async def run(self, target: Target) -> list[Finding]:
        if not target.config_path:
            return []
        cfg = parse_config(target.config_path)
        findings: list[Finding] = []

        auth_class = cfg.get("JupyterHub", "authenticator_class")
        if auth_class is None:
            return findings

        auth_str = str(auth_class)
        # Extract short name from fully qualified class names
        short_name = auth_str.rsplit(".", 1)[-1] if "." in auth_str else auth_str

        for name, desc in INSECURE_AUTHENTICATORS.items():
            if name.lower() in auth_str.lower():
                findings.append(Finding(
                    check_id=self.id,
                    severity=Severity.CRITICAL,
                    title=f"Insecure authenticator: {short_name}",
                    description=f"c.JupyterHub.authenticator_class = '{auth_str}'. {desc}",
                    evidence=f"authenticator_class = {auth_str}",
                    remediation=(
                        "Switch to a production authenticator (OAuthenticator, LDAPAuthenticator, etc.)."
                    ),
                    cwe=self.cwe,
                    references=self.references,
                    target_component="hub",
                ))

        for name, desc in WEAK_AUTHENTICATORS.items():
            if name.lower() in auth_str.lower():
                findings.append(Finding(
                    check_id=self.id,
                    severity=Severity.MEDIUM,
                    title=f"Potentially weak authenticator: {short_name}",
                    description=f"c.JupyterHub.authenticator_class = '{auth_str}'. {desc}",
                    evidence=f"authenticator_class = {auth_str}",
                    remediation="Consider using OAuthenticator with an established IdP for production.",
                    cwe=self.cwe,
                    references=self.references,
                    target_component="hub",
                ))

        return findings


class AuthenticatorSettingsCheck(BaseCheck):
    id = "config/authenticator-settings"
    title = "Authenticator settings are secure"
    severity = Severity.MEDIUM
    category = Category.CONFIG
    mode = "internal"
    references = [
        "https://jupyterhub.readthedocs.io/en/stable/reference/authenticators.html",
    ]

    async def run(self, target: Target) -> list[Finding]:
        if not target.config_path:
            return []
        cfg = parse_config(target.config_path)
        findings: list[Finding] = []

        allow_all = cfg.get("Authenticator", "allow_all")
        if allow_all is True:
            findings.append(Finding(
                check_id=self.id,
                severity=Severity.HIGH,
                title="Authenticator allows all users",
                description=(
                    "c.Authenticator.allow_all = True. Any user who can authenticate "
                    "with the identity provider can access JupyterHub."
                ),
                evidence="c.Authenticator.allow_all = True",
                remediation=(
                    "Set c.Authenticator.allowed_users or c.Authenticator.allow_all = False "
                    "to restrict access to an explicit allowlist."
                ),
                references=self.references,
                target_component="hub",
            ))

        for auth_cls in ("OAuthenticator", "GenericOAuthenticator", "GitHubOAuthenticator"):
            settings = cfg.get_class_settings(auth_cls)
            if not settings:
                continue

            client_secret = settings.get("client_secret")
            if isinstance(client_secret, str) and len(client_secret) > 0:
                findings.append(Finding(
                    check_id=self.id,
                    severity=Severity.HIGH,
                    title=f"OAuth client_secret hardcoded in config ({auth_cls})",
                    description=(
                        "The OAuth client secret is a literal string in jupyterhub_config.py. "
                        "If this file is in version control, the secret is exposed."
                    ),
                    evidence=f"c.{auth_cls}.client_secret = '<redacted>'",
                    remediation=(
                        "Use an environment variable: "
                        "c.OAuthenticator.client_secret = os.environ['OAUTH_CLIENT_SECRET']"
                    ),
                    cwe="CWE-798",
                    references=self.references,
                    target_component="hub",
                ))

        return findings

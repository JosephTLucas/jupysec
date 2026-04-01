"""Core JupyterHub configuration security audit."""

from __future__ import annotations

from jupysec.checks.base import BaseCheck
from jupysec.core.finding import Category, Finding, Severity
from jupysec.core.target import Target
from jupysec.utils.config_parser import parse_config


class CookieSecretCheck(BaseCheck):
    id = "config/cookie-secret"
    title = "Cookie secret is explicitly configured"
    severity = Severity.HIGH
    category = Category.CONFIG
    mode = "internal"
    references = [
        "https://jupyterhub.readthedocs.io/en/stable/tutorial/getting-started/security-basics.html",
    ]

    async def run(self, target: Target) -> list[Finding]:
        if not target.config_path:
            return []
        cfg = parse_config(target.config_path)
        if cfg.errors:
            return [Finding(
                check_id=self.id, severity=Severity.INFO,
                title="Config parse error",
                description="; ".join(cfg.errors),
                target_component="hub",
            )]

        has_secret = cfg.has("JupyterHub", "cookie_secret")
        has_file = cfg.has("JupyterHub", "cookie_secret_file")

        if not has_secret and not has_file:
            return [Finding(
                check_id=self.id,
                severity=Severity.HIGH,
                title="Cookie secret not configured",
                description=(
                    "Neither c.JupyterHub.cookie_secret nor c.JupyterHub.cookie_secret_file "
                    "is set. JupyterHub will auto-generate one, but it changes on restart, "
                    "invalidating all sessions and making deployments non-reproducible."
                ),
                remediation=(
                    "Generate a persistent secret: `openssl rand -hex 32 > /srv/jupyterhub/cookie_secret` "
                    "and set c.JupyterHub.cookie_secret_file = '/srv/jupyterhub/cookie_secret'"
                ),
                references=self.references,
                target_component="hub",
            )]
        return []


class ProxyTokenCheck(BaseCheck):
    id = "config/proxy-token"
    title = "Proxy authentication token is configured"
    severity = Severity.HIGH
    category = Category.CONFIG
    mode = "internal"
    references = [
        "https://jupyterhub.readthedocs.io/en/stable/tutorial/getting-started/security-basics.html",
    ]

    async def run(self, target: Target) -> list[Finding]:
        if not target.config_path:
            return []
        cfg = parse_config(target.config_path)
        if cfg.errors:
            return []

        if not cfg.has("ConfigurableHTTPProxy", "auth_token"):
            return [Finding(
                check_id=self.id,
                severity=Severity.HIGH,
                title="Proxy auth token not configured",
                description=(
                    "c.ConfigurableHTTPProxy.auth_token is not set. "
                    "Without it JupyterHub auto-generates one on each restart."
                ),
                remediation=(
                    "Set c.ConfigurableHTTPProxy.auth_token to a securely generated value: "
                    "`openssl rand -hex 32`"
                ),
                references=self.references,
                target_component="proxy",
            )]
        return []


class AllowRootCheck(BaseCheck):
    id = "config/allow-root"
    title = "Hub is not configured to run as root"
    severity = Severity.HIGH
    category = Category.CONFIG
    mode = "internal"
    cwe = "CWE-250"
    references = [
        "https://jupyterhub.readthedocs.io/en/stable/explanation/websecurity.html",
    ]

    async def run(self, target: Target) -> list[Finding]:
        if not target.config_path:
            return []
        cfg = parse_config(target.config_path)

        val = cfg.get("JupyterHub", "allow_root")
        if val is True:
            return [Finding(
                check_id=self.id,
                severity=Severity.HIGH,
                title="JupyterHub configured to allow running as root",
                description=(
                    "c.JupyterHub.allow_root = True. Running as root increases the "
                    "impact of any vulnerability in JupyterHub or its dependencies."
                ),
                evidence="c.JupyterHub.allow_root = True",
                remediation="Run JupyterHub as an unprivileged user. Remove c.JupyterHub.allow_root = True.",
                cwe=self.cwe,
                references=self.references,
                target_component="hub",
            )]
        return []


class AdminUsersCheck(BaseCheck):
    id = "config/admin-users"
    title = "Admin user list is explicit and minimal"
    severity = Severity.MEDIUM
    category = Category.CONFIG
    mode = "internal"
    cwe = "CWE-269"
    references = [
        "https://jupyterhub.readthedocs.io/en/stable/rbac/index.html",
    ]

    async def run(self, target: Target) -> list[Finding]:
        if not target.config_path:
            return []
        cfg = parse_config(target.config_path)
        findings: list[Finding] = []

        admin_access = cfg.get("JupyterHub", "admin_access")
        if admin_access is True:
            findings.append(Finding(
                check_id=self.id,
                severity=Severity.MEDIUM,
                title="Admin users can access all user servers",
                description=(
                    "c.JupyterHub.admin_access = True. Admin users can access any user's "
                    "notebook server, which may violate least-privilege."
                ),
                evidence="c.JupyterHub.admin_access = True",
                remediation=(
                    "Set c.JupyterHub.admin_access = False unless admins genuinely need "
                    "to impersonate users. Use RBAC scopes for finer control."
                ),
                cwe=self.cwe,
                references=self.references,
                target_component="hub",
            ))

        admin_users = cfg.get("Authenticator", "admin_users")
        if isinstance(admin_users, (list, set)) and len(admin_users) > 10:
            findings.append(Finding(
                check_id=self.id,
                severity=Severity.MEDIUM,
                title=f"Large admin user list ({len(admin_users)} users)",
                description=(
                    f"There are {len(admin_users)} admin users configured. "
                    "A large admin set increases the attack surface."
                ),
                evidence=f"admin_users count: {len(admin_users)}",
                remediation="Reduce the number of admin users to the minimum necessary.",
                cwe=self.cwe,
                references=self.references,
                target_component="hub",
            ))

        return findings

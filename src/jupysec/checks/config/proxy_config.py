"""Proxy configuration security audit."""

from __future__ import annotations

from jupysec.checks.base import BaseCheck
from jupysec.core.finding import Category, Finding, Severity
from jupysec.core.target import Target
from jupysec.utils.config_parser import parse_config


class BindAddressCheck(BaseCheck):
    id = "config/bind-address"
    title = "Hub/proxy not bound to all interfaces"
    severity = Severity.HIGH
    category = Category.CONFIG
    mode = "internal"
    cwe = "CWE-668"
    references = [
        "https://jupyterhub.readthedocs.io/en/stable/tutorial/getting-started/security-basics.html",
    ]

    async def run(self, target: Target) -> list[Finding]:
        if not target.config_path:
            return []
        cfg = parse_config(target.config_path)
        findings: list[Finding] = []

        bind_url = cfg.get("JupyterHub", "bind_url")
        ip = cfg.get("JupyterHub", "ip")

        for label, value in [("bind_url", bind_url), ("ip", ip)]:
            if isinstance(value, str) and ("0.0.0.0" in value or "::" in value):
                findings.append(Finding(
                    check_id=self.id,
                    severity=Severity.HIGH,
                    title=f"Hub bound to all interfaces via c.JupyterHub.{label}",
                    description=(
                        f"c.JupyterHub.{label} = '{value}' binds the Hub to all network "
                        "interfaces, potentially exposing it to untrusted networks."
                    ),
                    evidence=f"c.JupyterHub.{label} = '{value}'",
                    remediation=(
                        "Bind to 127.0.0.1 (or a private IP) and use a reverse proxy "
                        "for external access."
                    ),
                    cwe=self.cwe,
                    references=self.references,
                    target_component="hub",
                ))

        ssl_key = cfg.get("JupyterHub", "ssl_key")
        ssl_cert = cfg.get("JupyterHub", "ssl_cert")
        base_url = cfg.get("JupyterHub", "base_url")

        if not ssl_key and not ssl_cert:
            if bind_url and isinstance(bind_url, str) and "https" not in bind_url:
                findings.append(Finding(
                    check_id=self.id,
                    severity=Severity.MEDIUM,
                    title="No TLS configured on JupyterHub",
                    description=(
                        "Neither ssl_key/ssl_cert nor an https bind_url is configured. "
                        "If there is no TLS-terminating reverse proxy, traffic is unencrypted."
                    ),
                    remediation=(
                        "Configure TLS on the Hub or use a reverse proxy (nginx, traefik) "
                        "that terminates TLS."
                    ),
                    cwe="CWE-319",
                    references=self.references,
                    target_component="hub",
                ))

        return findings

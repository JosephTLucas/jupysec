"""Installed Jupyter extensions audit."""

from __future__ import annotations

import httpx

from jupysec.checks.base import BaseCheck
from jupysec.core.finding import Category, Finding, Severity
from jupysec.core.target import Target
from jupysec.utils.http import client_for

KNOWN_RISKY_EXTENSIONS = {
    "jupyter_server_proxy": (
        "Proxies arbitrary ports, expanding attack surface. "
        "Ensure it is updated (multiple critical CVEs in 2024)."
    ),
    "jupyterlab_git": (
        "Allows git operations from notebooks. Verify credentials "
        "aren't exposed and git hooks can't be abused."
    ),
    "nbgrader": (
        "Grading extension with elevated file access. Verify it runs "
        "with appropriate permissions."
    ),
}


class ExtensionsAuditCheck(BaseCheck):
    id = "supply/extensions"
    title = "Server extensions audited"
    severity = Severity.MEDIUM
    category = Category.SUPPLY_CHAIN
    mode = "both"
    references = [
        "https://jupyterhub.readthedocs.io/en/stable/explanation/websecurity.html",
    ]

    async def run(self, target: Target) -> list[Finding]:
        findings: list[Finding] = []
        extensions: dict[str, bool] = {}

        # External: try to enumerate from API
        if target.has_external:
            async with client_for(target) as client:
                try:
                    resp = await client.get("/api/config/ServerApp")
                    if resp.status_code == 200:
                        data = resp.json()
                        jpserver_extensions = data.get("jpserver_extensions", {})
                        if isinstance(jpserver_extensions, dict):
                            extensions.update(jpserver_extensions)
                except (httpx.HTTPError, ValueError):
                    pass

        # Internal: use importlib to find installed server extensions
        if target.has_internal:
            try:
                from importlib.metadata import entry_points

                eps = entry_points()
                server_eps = eps.get("jupyter_server.extension", []) if isinstance(eps, dict) else [
                    ep for ep in eps if ep.group == "jupyter_server.extension"
                ]
                for ep in server_eps:
                    extensions.setdefault(ep.name, True)
            except Exception:
                pass

        for ext_name, enabled in extensions.items():
            if not enabled:
                continue
            for risky_name, risk_desc in KNOWN_RISKY_EXTENSIONS.items():
                if risky_name in ext_name:
                    findings.append(Finding(
                        check_id=self.id,
                        severity=Severity.MEDIUM,
                        title=f"Extension with elevated risk: {ext_name}",
                        description=risk_desc,
                        evidence=f"Extension: {ext_name} (enabled: {enabled})",
                        remediation="Verify this extension is needed and up to date.",
                        references=self.references,
                        target_component="user-server",
                    ))

        if len(extensions) > 20:
            findings.append(Finding(
                check_id=self.id,
                severity=Severity.LOW,
                title=f"Large number of extensions installed ({len(extensions)})",
                description=(
                    "A large extension surface increases attack surface. "
                    "Each extension is additional code that can introduce vulnerabilities."
                ),
                evidence=f"Extension count: {len(extensions)}",
                remediation="Review and remove unnecessary extensions.",
                references=self.references,
                target_component="user-server",
            ))

        return findings


class ImageTrustCheck(BaseCheck):
    id = "supply/image-trust"
    title = "Container images are from trusted sources"
    severity = Severity.MEDIUM
    category = Category.SUPPLY_CHAIN
    mode = "internal"
    references = [
        "https://kubernetes.io/docs/concepts/containers/images/",
    ]

    async def run(self, target: Target) -> list[Finding]:
        if not target.config_path:
            return []

        from jupysec.utils.config_parser import parse_config

        cfg = parse_config(target.config_path)
        findings: list[Finding] = []

        for spawner_cls in ("KubeSpawner", "DockerSpawner"):
            image = cfg.get(spawner_cls, "image")
            if not isinstance(image, str):
                continue

            if ":" not in image or image.endswith(":latest"):
                findings.append(Finding(
                    check_id=self.id,
                    severity=Severity.MEDIUM,
                    title=f"Container image uses 'latest' tag: {image}",
                    description=(
                        f"c.{spawner_cls}.image = '{image}' uses the 'latest' tag "
                        "(or no tag). This makes builds non-reproducible and can "
                        "silently pull different images over time."
                    ),
                    evidence=f"c.{spawner_cls}.image = '{image}'",
                    remediation="Pin images to a specific digest or version tag.",
                    references=self.references,
                    target_component="spawner",
                ))

            allowed_registries = cfg.get(spawner_cls, "image_whitelist") or cfg.get(
                spawner_cls, "allowed_images"
            )
            if allowed_registries is None:
                profile_list = cfg.get(spawner_cls, "profile_list")
                if isinstance(profile_list, list) and len(profile_list) > 0:
                    # Profile-based image selection -- user might choose arbitrary images
                    pass  # This is actually the secure pattern
                else:
                    findings.append(Finding(
                        check_id=self.id,
                        severity=Severity.LOW,
                        title=f"No image allowlist on {spawner_cls}",
                        description=(
                            "No image_whitelist or allowed_images configured. "
                            "If users can influence the image, they could run untrusted code."
                        ),
                        remediation=f"Set c.{spawner_cls}.allowed_images to a list of trusted images.",
                        references=self.references,
                        target_component="spawner",
                    ))

        return findings

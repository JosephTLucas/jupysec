"""Check if user servers are directly accessible, bypassing Hub auth.

If the Jupyter notebook server is listening on a port reachable from the
network (not exclusively behind the Hub proxy), an attacker can bypass
all JupyterHub authentication by going directly to the user server.

This is an architecture-level vulnerability that generic scanners completely
miss -- they don't know that the Hub proxy is the security boundary.
"""

from __future__ import annotations

import httpx

from jupysec.checks.base import BaseCheck
from jupysec.core.finding import Category, Finding, Severity
from jupysec.core.target import Target
from jupysec.utils.http import client_for


class DirectServerAccessCheck(BaseCheck):
    id = "attack/direct-server-bypass"
    title = "User servers not directly accessible (Hub proxy is sole entry)"
    severity = Severity.CRITICAL
    category = Category.ISOLATION
    mode = "external"
    cwe = "CWE-288"
    references = [
        "https://jupyterhub.readthedocs.io/en/stable/explanation/websecurity.html",
    ]

    def prerequisites_met(self, target: Target) -> bool:
        return target.has_external and target.token is not None

    async def run(self, target: Target) -> list[Finding]:
        findings: list[Finding] = []

        # Get proxy routes to find user server targets
        async with client_for(target) as client:
            try:
                resp = await client.get("/hub/api/proxy")
                if resp.status_code != 200:
                    return findings
                routes = resp.json()
            except (httpx.HTTPError, ValueError):
                return findings

        # Extract user server backend URLs from proxy routes
        server_urls: list[tuple[str, str]] = []
        for route_path, route_info in routes.items():
            if "/user/" not in route_path:
                continue
            if isinstance(route_info, dict):
                backend = route_info.get("target", "")
                if backend:
                    server_urls.append((route_path, backend))

        # Try to reach user server backends directly (without Hub proxy auth)
        for route_path, backend_url in server_urls[:5]:
            try:
                async with httpx.AsyncClient(
                    verify=False, timeout=5.0, follow_redirects=True,
                ) as direct_client:
                    resp = await direct_client.get(f"{backend_url}/api")
                    if resp.status_code == 200:
                        findings.append(Finding(
                            check_id=self.id,
                            severity=Severity.CRITICAL,
                            title=f"User server directly accessible at {backend_url}",
                            description=(
                                f"The user server behind route '{route_path}' is directly "
                                f"reachable at {backend_url} without going through the Hub "
                                f"proxy. An attacker on the network can bypass all Hub "
                                f"authentication and directly execute code."
                            ),
                            evidence=f"GET {backend_url}/api -> {resp.status_code}",
                            remediation=(
                                "Ensure user servers bind to localhost or a pod-internal IP only. "
                                "Use NetworkPolicies to block direct ingress to user pods. "
                                "The Hub proxy should be the sole entry point."
                            ),
                            cwe=self.cwe,
                            references=self.references,
                            target_component="proxy",
                        ))
                        break  # One finding is sufficient
            except httpx.HTTPError:
                continue  # Not reachable directly = good

        return findings


class SharedStorageCheck(BaseCheck):
    """Check for shared storage between users (config-based).

    If multiple users share a PVC or NFS volume, User A can inject malicious
    code into User B's notebooks. This is a lateral movement vector.
    """

    id = "attack/shared-storage"
    title = "Users do not share writable storage"
    severity = Severity.HIGH
    category = Category.ISOLATION
    mode = "internal"
    cwe = "CWE-284"
    references = [
        "https://jupyterhub.readthedocs.io/en/stable/explanation/websecurity.html",
    ]

    async def run(self, target: Target) -> list[Finding]:
        if not target.config_path:
            return []

        from jupysec.utils.config_parser import parse_config

        cfg = parse_config(target.config_path)
        findings: list[Finding] = []

        for spawner_cls in ("KubeSpawner", "DockerSpawner"):
            settings = cfg.get_class_settings(spawner_cls)
            if not settings:
                continue

            volumes = settings.get("volumes") or []
            volume_mounts = settings.get("volume_mounts") or []
            storage_class = settings.get("storage_class")
            storage_access = settings.get("storage_access_modes")

            # Check for NFS or ReadWriteMany (shared storage)
            if isinstance(storage_access, list):
                for mode in storage_access:
                    if isinstance(mode, str) and "readwritemany" in mode.lower():
                        findings.append(Finding(
                            check_id=self.id,
                            severity=Severity.HIGH,
                            title=f"ReadWriteMany storage on {spawner_cls}",
                            description=(
                                "Storage access mode is ReadWriteMany, meaning multiple "
                                "user pods can write to the same volume. User A can modify "
                                "User B's notebooks to inject malicious code."
                            ),
                            evidence=f"c.{spawner_cls}.storage_access_modes = {storage_access}",
                            remediation=(
                                "Use ReadWriteOnce (RWO) with per-user PVCs. "
                                "If shared storage is needed, mount it read-only."
                            ),
                            cwe=self.cwe,
                            references=self.references,
                            target_component="spawner",
                        ))

            # Check for shared volume mounts
            if isinstance(volumes, list):
                for vol in volumes:
                    if isinstance(vol, dict):
                        nfs = vol.get("nfs") or vol.get("nfsServer")
                        if nfs:
                            findings.append(Finding(
                                check_id=self.id,
                                severity=Severity.HIGH,
                                title=f"NFS volume in {spawner_cls}",
                                description=(
                                    "An NFS volume is mounted into user pods. If multiple "
                                    "users share the same NFS export, they can attack each "
                                    "other via file manipulation (malicious notebooks, symlink "
                                    "attacks, etc.)."
                                ),
                                evidence=f"NFS volume: {vol}",
                                remediation="Use per-user subdirectories with strict permissions, or separate PVCs.",
                                cwe=self.cwe,
                                references=self.references,
                                target_component="spawner",
                            ))

        return findings

"""Spawner configuration security audit."""

from __future__ import annotations

from jupysec.checks.base import BaseCheck
from jupysec.core.finding import Category, Finding, Severity
from jupysec.core.target import Target
from jupysec.utils.config_parser import parse_config


class SpawnerLimitsCheck(BaseCheck):
    id = "config/spawner-limits"
    title = "Spawner enforces resource limits"
    severity = Severity.MEDIUM
    category = Category.CONFIG
    mode = "internal"
    references = [
        "https://z2jh.jupyter.org/en/stable/administrator/security.html",
    ]

    async def run(self, target: Target) -> list[Finding]:
        if not target.config_path:
            return []
        cfg = parse_config(target.config_path)
        findings: list[Finding] = []

        for spawner_cls in ("Spawner", "KubeSpawner", "DockerSpawner", "SystemdSpawner"):
            settings = cfg.get_class_settings(spawner_cls)
            if not settings:
                continue

            has_mem = "mem_limit" in settings or "memory_limit" in settings
            has_cpu = "cpu_limit" in settings

            if not has_mem:
                findings.append(Finding(
                    check_id=self.id,
                    severity=Severity.MEDIUM,
                    title=f"No memory limit on {spawner_cls}",
                    description=(
                        f"c.{spawner_cls} does not set mem_limit / memory_limit. "
                        "A user could exhaust host memory."
                    ),
                    remediation=f"Set c.{spawner_cls}.mem_limit = '2G' (adjust to your environment).",
                    references=self.references,
                    target_component="spawner",
                ))

            if not has_cpu:
                findings.append(Finding(
                    check_id=self.id,
                    severity=Severity.LOW,
                    title=f"No CPU limit on {spawner_cls}",
                    description=(
                        f"c.{spawner_cls} does not set cpu_limit. "
                        "A user could monopolize CPU."
                    ),
                    remediation=f"Set c.{spawner_cls}.cpu_limit = 2 (adjust to your environment).",
                    references=self.references,
                    target_component="spawner",
                ))

        return findings


class SpawnerPrivilegedCheck(BaseCheck):
    id = "config/spawner-privileged"
    title = "Spawner does not run privileged containers"
    severity = Severity.CRITICAL
    category = Category.CONFIG
    mode = "internal"
    cwe = "CWE-250"
    references = [
        "https://kubernetes.io/docs/concepts/security/pod-security-standards/",
    ]

    async def run(self, target: Target) -> list[Finding]:
        if not target.config_path:
            return []
        cfg = parse_config(target.config_path)
        findings: list[Finding] = []

        for spawner_cls in ("KubeSpawner", "DockerSpawner"):
            settings = cfg.get_class_settings(spawner_cls)
            if not settings:
                continue

            privileged = settings.get("privileged")
            if privileged is True:
                findings.append(Finding(
                    check_id=self.id,
                    severity=Severity.CRITICAL,
                    title=f"{spawner_cls} runs privileged containers",
                    description=(
                        f"c.{spawner_cls}.privileged = True. Privileged containers have "
                        "full access to the host kernel, enabling trivial container escape."
                    ),
                    evidence=f"c.{spawner_cls}.privileged = True",
                    remediation=f"Set c.{spawner_cls}.privileged = False.",
                    cwe=self.cwe,
                    references=self.references,
                    target_component="spawner",
                ))

            extra_container = settings.get("extra_container_config")
            if isinstance(extra_container, dict) and extra_container.get("privileged") is True:
                findings.append(Finding(
                    check_id=self.id,
                    severity=Severity.CRITICAL,
                    title=f"{spawner_cls} extra_container_config enables privileged",
                    description=f"Privileged mode set via c.{spawner_cls}.extra_container_config.",
                    evidence=f"extra_container_config: {extra_container}",
                    remediation="Remove 'privileged: True' from extra_container_config.",
                    cwe=self.cwe,
                    references=self.references,
                    target_component="spawner",
                ))

            uid = settings.get("uid")
            if uid == 0:
                findings.append(Finding(
                    check_id=self.id,
                    severity=Severity.HIGH,
                    title=f"{spawner_cls} runs containers as root (uid=0)",
                    description=f"c.{spawner_cls}.uid = 0. User containers run as root.",
                    evidence=f"c.{spawner_cls}.uid = 0",
                    remediation=f"Set c.{spawner_cls}.uid to a non-zero value (e.g. 1000).",
                    cwe=self.cwe,
                    references=self.references,
                    target_component="spawner",
                ))

        return findings

"""Kubernetes secrets security checks."""

from __future__ import annotations

from jupysec.checks.base import BaseCheck
from jupysec.core.finding import Category, Finding, Severity
from jupysec.core.target import Target

SENSITIVE_SECRET_PATTERNS = [
    "cookie-secret", "proxy-token", "hub-secret",
    "oauth", "tls", "database", "postgres",
]


class SecretsCheck(BaseCheck):
    id = "k8s/secrets-security"
    title = "Kubernetes secrets are properly managed"
    severity = Severity.MEDIUM
    category = Category.KUBERNETES
    mode = "internal"
    cwe = "CWE-312"
    references = [
        "https://kubernetes.io/docs/concepts/configuration/secret/",
    ]

    def prerequisites_met(self, target: Target) -> bool:
        return target.kubeconfig is not None or target.namespace is not None

    async def run(self, target: Target) -> list[Finding]:
        from jupysec.utils.kubernetes import k8s_client

        findings: list[Finding] = []
        ns = target.namespace or "default"

        try:
            with k8s_client(target.kubeconfig) as client:
                v1 = client.CoreV1Api()
                secrets = v1.list_namespaced_secret(ns)
        except ImportError as exc:
            return [Finding(
                check_id=self.id, severity=Severity.INFO,
                title="Kubernetes client not available",
                description=str(exc), target_component="kubernetes",
            )]
        except Exception as exc:
            return [Finding(
                check_id=self.id, severity=Severity.INFO,
                title="Could not query Kubernetes API",
                description=str(exc), target_component="kubernetes",
            )]

        opaque_count = 0
        for secret in secrets.items:
            if secret.type == "Opaque":
                opaque_count += 1
                name = secret.metadata.name
                for pattern in SENSITIVE_SECRET_PATTERNS:
                    if pattern in name.lower():
                        annotations = secret.metadata.annotations or {}
                        if not annotations.get("kubectl.kubernetes.io/last-applied-configuration"):
                            continue
                        # Secrets created from plain manifests (not sealed/external)
                        findings.append(Finding(
                            check_id=self.id,
                            severity=Severity.MEDIUM,
                            title=f"Secret '{name}' may be stored in plain manifests",
                            description=(
                                f"The secret '{name}' appears to be managed via kubectl apply "
                                "with last-applied-configuration, which stores the full secret "
                                "value in an annotation. This effectively stores the secret "
                                "in plaintext."
                            ),
                            evidence=f"Secret '{name}' has last-applied-configuration annotation",
                            remediation=(
                                "Use SealedSecrets, ExternalSecrets, or Vault to manage "
                                "secrets instead of plain kubectl apply."
                            ),
                            cwe=self.cwe,
                            references=self.references,
                            target_component="kubernetes",
                        ))
                        break

        return findings


class ResourceLimitsCheck(BaseCheck):
    id = "k8s/resource-limits"
    title = "User pods have resource limits"
    severity = Severity.MEDIUM
    category = Category.KUBERNETES
    mode = "internal"
    references = [
        "https://z2jh.jupyter.org/en/stable/administrator/security.html",
    ]

    def prerequisites_met(self, target: Target) -> bool:
        return target.kubeconfig is not None or target.namespace is not None

    async def run(self, target: Target) -> list[Finding]:
        from jupysec.utils.kubernetes import k8s_client

        findings: list[Finding] = []
        ns = target.namespace or "default"

        try:
            with k8s_client(target.kubeconfig) as client:
                v1 = client.CoreV1Api()
                pods = v1.list_namespaced_pod(ns, label_selector="component=singleuser-server")
        except ImportError as exc:
            return [Finding(
                check_id=self.id, severity=Severity.INFO,
                title="Kubernetes client not available",
                description=str(exc), target_component="kubernetes",
            )]
        except Exception as exc:
            return [Finding(
                check_id=self.id, severity=Severity.INFO,
                title="Could not query Kubernetes API",
                description=str(exc), target_component="kubernetes",
            )]

        if not pods.items:
            # Also try the app=jupyterhub,component=singleuser-server pattern
            try:
                with k8s_client(target.kubeconfig) as client:
                    v1 = client.CoreV1Api()
                    pods = v1.list_namespaced_pod(ns, label_selector="app=jupyterhub")
            except Exception:
                return findings

        for pod in pods.items:
            pod_name = pod.metadata.name
            for container in pod.spec.containers:
                limits = container.resources.limits if container.resources else None
                if not limits:
                    findings.append(Finding(
                        check_id=self.id,
                        severity=Severity.MEDIUM,
                        title=f"No resource limits on {pod_name}/{container.name}",
                        description=(
                            f"Container '{container.name}' in pod '{pod_name}' has no "
                            "resource limits. A user could exhaust node resources."
                        ),
                        remediation="Set resource limits in the spawner config or LimitRange.",
                        references=self.references,
                        target_component="kubernetes",
                    ))
                else:
                    if "memory" not in limits:
                        findings.append(Finding(
                            check_id=self.id,
                            severity=Severity.MEDIUM,
                            title=f"No memory limit on {pod_name}/{container.name}",
                            description=f"Container '{container.name}' has no memory limit.",
                            remediation="Add memory limit to spawner config.",
                            references=self.references,
                            target_component="kubernetes",
                        ))

        return findings

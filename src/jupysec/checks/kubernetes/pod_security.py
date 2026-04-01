"""Kubernetes Pod Security standards enforcement."""

from __future__ import annotations

from jupysec.checks.base import BaseCheck
from jupysec.core.finding import Category, Finding, Severity
from jupysec.core.target import Target


class PodSecurityCheck(BaseCheck):
    id = "k8s/pod-security"
    title = "Pod Security standards enforced"
    severity = Severity.HIGH
    category = Category.KUBERNETES
    mode = "internal"
    references = [
        "https://kubernetes.io/docs/concepts/security/pod-security-standards/",
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
                ns_obj = v1.read_namespace(ns)
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

        labels = ns_obj.metadata.labels or {}

        enforce = labels.get("pod-security.kubernetes.io/enforce", "")
        audit = labels.get("pod-security.kubernetes.io/audit", "")
        warn = labels.get("pod-security.kubernetes.io/warn", "")

        if not enforce:
            findings.append(Finding(
                check_id=self.id,
                severity=Severity.HIGH,
                title=f"No Pod Security enforce label on namespace '{ns}'",
                description=(
                    "The namespace lacks a pod-security.kubernetes.io/enforce label. "
                    "Without it, Kubernetes does not enforce Pod Security Standards, "
                    "and user pods could run as root or with host access."
                ),
                evidence=f"Namespace labels: {labels}",
                remediation=(
                    "Add label: pod-security.kubernetes.io/enforce=restricted "
                    "(or 'baseline' as a minimum)."
                ),
                references=self.references,
                target_component="kubernetes",
            ))
        elif enforce == "privileged":
            findings.append(Finding(
                check_id=self.id,
                severity=Severity.HIGH,
                title=f"Pod Security set to 'privileged' on namespace '{ns}'",
                description="The 'privileged' profile imposes no restrictions on pods.",
                evidence=f"pod-security.kubernetes.io/enforce=privileged",
                remediation="Use 'restricted' or at minimum 'baseline'.",
                references=self.references,
                target_component="kubernetes",
            ))

        if not audit and not warn:
            findings.append(Finding(
                check_id=self.id,
                severity=Severity.LOW,
                title="No Pod Security audit/warn labels",
                description="Consider adding audit and warn labels for visibility into violations.",
                remediation="Add pod-security.kubernetes.io/audit=restricted and /warn=restricted.",
                references=self.references,
                target_component="kubernetes",
            ))

        return findings

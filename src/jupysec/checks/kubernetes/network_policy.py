"""Kubernetes NetworkPolicy checks for user pod isolation."""

from __future__ import annotations

from jupysec.checks.base import BaseCheck
from jupysec.core.finding import Category, Finding, Severity
from jupysec.core.target import Target


class NetworkPolicyCheck(BaseCheck):
    id = "k8s/network-policy"
    title = "NetworkPolicies exist for user pods"
    severity = Severity.HIGH
    category = Category.KUBERNETES
    mode = "internal"
    references = [
        "https://z2jh.jupyter.org/en/stable/administrator/security.html",
        "https://github.com/jupyterhub/zero-to-jupyterhub-k8s/pull/2508",
    ]

    def prerequisites_met(self, target: Target) -> bool:
        return target.kubeconfig is not None or target.namespace is not None

    async def run(self, target: Target) -> list[Finding]:
        from jupysec.utils.kubernetes import k8s_client

        findings: list[Finding] = []
        ns = target.namespace or "default"

        try:
            with k8s_client(target.kubeconfig) as client:
                net_api = client.NetworkingV1Api()
                policies = net_api.list_namespaced_network_policy(ns)
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

        if not policies.items:
            findings.append(Finding(
                check_id=self.id,
                severity=Severity.HIGH,
                title=f"No NetworkPolicies in namespace '{ns}'",
                description=(
                    f"No NetworkPolicy resources found in namespace '{ns}'. "
                    "Without NetworkPolicies, user pods can communicate freely with "
                    "each other, the Hub database, and internal cluster services."
                ),
                remediation=(
                    "Deploy NetworkPolicies to restrict user pod egress. "
                    "Z2JH Helm chart provides these by default -- ensure "
                    "networkPolicy.enabled is true in your values.yaml."
                ),
                references=self.references,
                target_component="kubernetes",
            ))
            return findings

        has_egress_policy = any(
            p.spec and p.spec.policy_types and "Egress" in p.spec.policy_types
            for p in policies.items
        )
        if not has_egress_policy:
            findings.append(Finding(
                check_id=self.id,
                severity=Severity.MEDIUM,
                title="No egress NetworkPolicy found",
                description=(
                    "NetworkPolicies exist but none restrict Egress traffic. "
                    "User pods can reach arbitrary internal endpoints."
                ),
                remediation=(
                    "Add an Egress policy that denies traffic to private IP ranges "
                    "by default (Z2JH's egressAllowRules pattern)."
                ),
                references=self.references,
                target_component="kubernetes",
            ))

        return findings

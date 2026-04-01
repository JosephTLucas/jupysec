"""Kubernetes RBAC checks for JupyterHub service accounts."""

from __future__ import annotations

from jupysec.checks.base import BaseCheck
from jupysec.core.finding import Category, Finding, Severity
from jupysec.core.target import Target

DANGEROUS_VERBS = {"*", "create", "delete", "patch", "update"}
DANGEROUS_RESOURCES = {"*", "secrets", "pods/exec", "nodes", "clusterroles", "clusterrolebindings"}


class RBACMinimalCheck(BaseCheck):
    id = "k8s/rbac-minimal"
    title = "ServiceAccounts have minimal RBAC permissions"
    severity = Severity.HIGH
    category = Category.KUBERNETES
    mode = "internal"
    cwe = "CWE-269"
    references = [
        "https://kubernetes.io/docs/reference/access-authn-authz/rbac/",
    ]

    def prerequisites_met(self, target: Target) -> bool:
        return target.kubeconfig is not None or target.namespace is not None

    async def run(self, target: Target) -> list[Finding]:
        from jupysec.utils.kubernetes import k8s_client

        findings: list[Finding] = []
        ns = target.namespace or "default"

        try:
            with k8s_client(target.kubeconfig) as client:
                rbac = client.RbacAuthorizationV1Api()
                bindings = rbac.list_namespaced_role_binding(ns)
                cluster_bindings = rbac.list_cluster_role_binding()
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

        sa_roles: dict[str, list[str]] = {}

        for b in bindings.items:
            if not b.subjects:
                continue
            for subj in b.subjects:
                if subj.kind == "ServiceAccount" and subj.namespace == ns:
                    role_name = b.role_ref.name
                    sa_roles.setdefault(subj.name, []).append(f"Role/{role_name}")

        for b in cluster_bindings.items:
            if not b.subjects:
                continue
            for subj in b.subjects:
                if subj.kind == "ServiceAccount" and getattr(subj, "namespace", None) == ns:
                    role_name = b.role_ref.name
                    sa_roles.setdefault(subj.name, []).append(f"ClusterRole/{role_name}")

                    if b.role_ref.name in ("cluster-admin", "admin"):
                        findings.append(Finding(
                            check_id=self.id,
                            severity=Severity.CRITICAL,
                            title=f"ServiceAccount '{subj.name}' bound to ClusterRole/{b.role_ref.name}",
                            description=(
                                f"The service account '{subj.name}' in namespace '{ns}' "
                                f"is bound to the '{b.role_ref.name}' ClusterRole, granting "
                                "broad cluster-wide permissions."
                            ),
                            evidence=f"ClusterRoleBinding: {b.metadata.name}",
                            remediation="Use namespace-scoped roles with minimal permissions.",
                            cwe=self.cwe,
                            references=self.references,
                            target_component="kubernetes",
                        ))

        return findings

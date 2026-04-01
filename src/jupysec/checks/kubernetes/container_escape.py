"""Container escape vector analysis.

Checks for ALL known container escape paths in user pods, not just
`privileged: true`. An attacker who gets code execution in a notebook
will look for these.
"""

from __future__ import annotations

from jupysec.checks.base import BaseCheck
from jupysec.core.finding import Category, Finding, Severity
from jupysec.core.target import Target

DANGEROUS_CAPABILITIES = {
    "SYS_ADMIN", "SYS_PTRACE", "SYS_RAWIO", "DAC_OVERRIDE",
    "NET_ADMIN", "NET_RAW",
}

DANGEROUS_HOST_PATHS = [
    "/", "/etc", "/var/run/docker.sock", "/var/run/crio",
    "/var/run/containerd", "/proc", "/sys",
    "/var/lib/kubelet", "/var/lib/docker",
]


class ContainerEscapeCheck(BaseCheck):
    """Inspect running user pods for container escape vectors.

    Goes far beyond `privileged: true` to check:
    - hostPath volume mounts (docker socket, host root, etc.)
    - Dangerous Linux capabilities
    - hostPID / hostNetwork / hostIPC
    - Service account token auto-mount
    - Writable /proc or /sys
    """

    id = "attack/container-escape"
    title = "User pods checked for container escape vectors"
    severity = Severity.CRITICAL
    category = Category.KUBERNETES
    mode = "internal"
    cwe = "CWE-250"
    references = [
        "https://kubernetes.io/docs/concepts/security/pod-security-standards/",
        "https://bishopfox.com/blog/kubernetes-pod-privilege-escalation",
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
                pods = v1.list_namespaced_pod(
                    ns, label_selector="component=singleuser-server"
                )
                if not pods.items:
                    pods = v1.list_namespaced_pod(
                        ns, label_selector="app=jupyterhub"
                    )
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

        for pod in pods.items:
            pod_name = pod.metadata.name
            spec = pod.spec

            # hostPID / hostNetwork / hostIPC
            if spec.host_pid:
                findings.append(self._finding(
                    f"hostPID enabled on {pod_name}",
                    "hostPID shares the host PID namespace, allowing visibility into "
                    "all host processes and enabling ptrace-based attacks.",
                    f"pod/{pod_name}: hostPID=true",
                    "Remove hostPID from spawner pod spec.",
                ))
            if spec.host_network:
                findings.append(self._finding(
                    f"hostNetwork enabled on {pod_name}",
                    "hostNetwork bypasses all NetworkPolicies and exposes all host ports.",
                    f"pod/{pod_name}: hostNetwork=true",
                    "Remove hostNetwork from spawner pod spec.",
                ))
            if spec.host_ipc:
                findings.append(self._finding(
                    f"hostIPC enabled on {pod_name}",
                    "hostIPC shares host IPC namespace, enabling cross-container communication.",
                    f"pod/{pod_name}: hostIPC=true",
                    "Remove hostIPC from spawner pod spec.",
                ))

            # Service account token auto-mount
            if spec.automount_service_account_token is not False:
                sa_name = spec.service_account_name or "default"
                findings.append(Finding(
                    check_id=self.id,
                    severity=Severity.MEDIUM,
                    title=f"SA token auto-mounted in {pod_name} (sa: {sa_name})",
                    description=(
                        f"The service account token for '{sa_name}' is mounted into the "
                        f"user pod. An attacker in a notebook can use it to authenticate "
                        f"to the Kubernetes API."
                    ),
                    evidence=f"pod/{pod_name}: automountServiceAccountToken != false",
                    remediation=(
                        "Set automountServiceAccountToken: false on user pods. "
                        "In KubeSpawner: c.KubeSpawner.automount_service_account_token = False"
                    ),
                    cwe=self.cwe,
                    references=self.references,
                    target_component="kubernetes",
                ))

            # Volume mounts
            for vol in spec.volumes or []:
                if vol.host_path:
                    hp = vol.host_path.path
                    is_dangerous = any(
                        hp == d or hp.startswith(d + "/")
                        for d in DANGEROUS_HOST_PATHS
                    )
                    if is_dangerous:
                        findings.append(self._finding(
                            f"Dangerous hostPath mount: {hp} in {pod_name}",
                            f"hostPath volume mounts '{hp}' into the user pod. "
                            f"{'Docker socket access enables full container escape.' if 'docker.sock' in hp else 'This grants access to sensitive host files.'} ",
                            f"pod/{pod_name}: hostPath={hp}",
                            f"Remove the hostPath volume mount for '{hp}'. "
                            f"Use emptyDir, PVC, or projected volumes instead.",
                        ))

            # Container security contexts
            for container in spec.containers:
                sc = container.security_context
                if not sc:
                    continue

                if sc.privileged:
                    findings.append(self._finding(
                        f"Privileged container: {pod_name}/{container.name}",
                        "Container runs in privileged mode with full kernel access.",
                        f"pod/{pod_name}/{container.name}: privileged=true",
                        "Set securityContext.privileged: false.",
                    ))

                if sc.capabilities and sc.capabilities.add:
                    dangerous = set(sc.capabilities.add) & DANGEROUS_CAPABILITIES
                    if dangerous:
                        findings.append(self._finding(
                            f"Dangerous capabilities on {pod_name}/{container.name}: {dangerous}",
                            f"Container has capabilities {dangerous} that may enable "
                            f"container escape or network attacks.",
                            f"pod/{pod_name}/{container.name}: capabilities.add={list(sc.capabilities.add)}",
                            f"Remove capabilities: {dangerous}. Use 'drop: [ALL]' and add only what's needed.",
                        ))

                if sc.run_as_user == 0 or (sc.run_as_non_root is not True and not sc.run_as_user):
                    findings.append(Finding(
                        check_id=self.id,
                        severity=Severity.MEDIUM,
                        title=f"Container may run as root: {pod_name}/{container.name}",
                        description="Container does not enforce runAsNonRoot or runs as uid 0.",
                        evidence=f"runAsUser={sc.run_as_user}, runAsNonRoot={sc.run_as_non_root}",
                        remediation="Set securityContext.runAsNonRoot: true and runAsUser: 1000.",
                        cwe=self.cwe,
                        references=self.references,
                        target_component="kubernetes",
                    ))

        return findings

    def _finding(self, title: str, desc: str, evidence: str, remediation: str) -> Finding:
        return Finding(
            check_id=self.id,
            severity=Severity.CRITICAL,
            title=title,
            description=desc,
            evidence=evidence,
            remediation=remediation,
            cwe=self.cwe,
            references=self.references,
            target_component="kubernetes",
        )

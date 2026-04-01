"""JupyterHub Security Benchmark definitions.

Modeled after CIS Benchmarks: each benchmark item maps to one or more checks
and provides a pass/fail/warn assessment with remediation guidance.
"""

from __future__ import annotations

from dataclasses import dataclass, field


@dataclass
class BenchmarkItem:
    id: str
    title: str
    section: str
    description: str
    check_ids: list[str] = field(default_factory=list)
    level: int = 1  # 1 = essential, 2 = hardening


JUPYTERHUB_BENCHMARK: list[BenchmarkItem] = [
    # Section 1: Authentication
    BenchmarkItem(
        id="JHB-1.1",
        title="API authentication is enforced",
        section="1. Authentication",
        description="All Hub API endpoints must reject unauthenticated requests.",
        check_ids=["auth/token-required", "api/endpoint-enum"],
    ),
    BenchmarkItem(
        id="JHB-1.2",
        title="Production authenticator is configured",
        section="1. Authentication",
        description="DummyAuthenticator and NullAuthenticator must not be used.",
        check_ids=["config/authenticator-type"],
    ),
    BenchmarkItem(
        id="JHB-1.3",
        title="Session cookies are secured",
        section="1. Authentication",
        description="Cookies must have Secure, HttpOnly, and SameSite attributes.",
        check_ids=["auth/cookie-flags"],
    ),
    BenchmarkItem(
        id="JHB-1.4",
        title="Cookie secret is persistent",
        section="1. Authentication",
        description="Cookie secret must be explicitly configured, not auto-generated.",
        check_ids=["config/cookie-secret"],
    ),
    BenchmarkItem(
        id="JHB-1.5",
        title="Privilege escalation is prevented",
        section="1. Authentication",
        description="Non-admin users cannot escalate to admin (CVE-2024-41942).",
        check_ids=["auth/admin-escalation"],
    ),

    # Section 2: Transport Security
    BenchmarkItem(
        id="JHB-2.1",
        title="TLS is properly configured",
        section="2. Transport Security",
        description="TLS 1.2+ with strong ciphers and valid certificate.",
        check_ids=["network/tls-config"],
    ),
    BenchmarkItem(
        id="JHB-2.2",
        title="CORS policy is restrictive",
        section="2. Transport Security",
        description="Access-Control-Allow-Origin must not be wildcard or reflect arbitrary origins.",
        check_ids=["network/cors-policy"],
    ),
    BenchmarkItem(
        id="JHB-2.3",
        title="CSP header is present",
        section="2. Transport Security",
        description="Content-Security-Policy should be set to mitigate XSS.",
        check_ids=["network/csp-policy"],
        level=2,
    ),

    # Section 3: API Security
    BenchmarkItem(
        id="JHB-3.1",
        title="XSRF protection is active",
        section="3. API Security",
        description="State-changing requests must require XSRF tokens.",
        check_ids=["api/xsrf-enforcement"],
    ),
    BenchmarkItem(
        id="JHB-3.2",
        title="API does not disclose sensitive info",
        section="3. API Security",
        description="Version info and internal details are not exposed to unauthenticated users.",
        check_ids=["api/info-disclosure", "api/version-headers"],
        level=2,
    ),
    BenchmarkItem(
        id="JHB-3.3",
        title="API permissions follow least-privilege",
        section="3. API Security",
        description="Tokens should have minimal scopes.",
        check_ids=["api/permission-probe"],
    ),

    # Section 4: User Isolation
    BenchmarkItem(
        id="JHB-4.1",
        title="Cross-user API access is blocked",
        section="4. User Isolation",
        description="Users cannot access other users' server APIs.",
        check_ids=["isolation/cross-user"],
    ),
    BenchmarkItem(
        id="JHB-4.2",
        title="WebSocket endpoints are authenticated",
        section="4. User Isolation",
        description="Kernel and terminal WebSockets require valid credentials.",
        check_ids=["ws/kernel-auth"],
    ),
    BenchmarkItem(
        id="JHB-4.3",
        title="Cross-user kernel access is blocked",
        section="4. User Isolation",
        description="Users cannot connect to other users' kernel WebSockets.",
        check_ids=["ws/kernel-isolation"],
    ),

    # Section 5: Deployment Configuration
    BenchmarkItem(
        id="JHB-5.1",
        title="Hub does not run as root",
        section="5. Deployment Configuration",
        description="JupyterHub should run as an unprivileged user.",
        check_ids=["config/allow-root"],
    ),
    BenchmarkItem(
        id="JHB-5.2",
        title="Resource limits are configured",
        section="5. Deployment Configuration",
        description="Spawner must enforce CPU and memory limits.",
        check_ids=["config/spawner-limits"],
    ),
    BenchmarkItem(
        id="JHB-5.3",
        title="Containers are not privileged",
        section="5. Deployment Configuration",
        description="User containers must not run in privileged mode.",
        check_ids=["config/spawner-privileged"],
    ),
    BenchmarkItem(
        id="JHB-5.4",
        title="Admin access is minimized",
        section="5. Deployment Configuration",
        description="Admin user list should be small and admin_access should be false.",
        check_ids=["config/admin-users"],
        level=2,
    ),
    BenchmarkItem(
        id="JHB-5.5",
        title="Proxy token is configured",
        section="5. Deployment Configuration",
        description="ConfigurableHTTPProxy auth_token should be explicitly set.",
        check_ids=["config/proxy-token"],
    ),
    BenchmarkItem(
        id="JHB-5.6",
        title="Hub is not bound to all interfaces",
        section="5. Deployment Configuration",
        description="Hub should bind to localhost or a private IP.",
        check_ids=["config/bind-address"],
    ),

    # Section 6: Kubernetes
    BenchmarkItem(
        id="JHB-6.1",
        title="NetworkPolicies restrict user pods",
        section="6. Kubernetes",
        description="NetworkPolicies must exist to restrict inter-pod and egress traffic.",
        check_ids=["k8s/network-policy"],
    ),
    BenchmarkItem(
        id="JHB-6.2",
        title="Pod Security Standards enforced",
        section="6. Kubernetes",
        description="Namespace must have Pod Security enforce label (restricted or baseline).",
        check_ids=["k8s/pod-security"],
    ),
    BenchmarkItem(
        id="JHB-6.3",
        title="RBAC follows least-privilege",
        section="6. Kubernetes",
        description="Service accounts should not be bound to cluster-admin.",
        check_ids=["k8s/rbac-minimal"],
    ),

    # Section 7: Supply Chain
    BenchmarkItem(
        id="JHB-7.1",
        title="No known CVEs in installed versions",
        section="7. Supply Chain",
        description="All Jupyter components should be updated past known CVEs.",
        check_ids=["supply/cve-check"],
    ),
    BenchmarkItem(
        id="JHB-7.2",
        title="Extensions are audited",
        section="7. Supply Chain",
        description="Installed server extensions should be reviewed for trust.",
        check_ids=["supply/extensions"],
        level=2,
    ),
    BenchmarkItem(
        id="JHB-7.3",
        title="Container images are trusted and pinned",
        section="7. Supply Chain",
        description="User container images should use specific tags and come from trusted registries.",
        check_ids=["supply/image-trust"],
        level=2,
    ),
]


def get_benchmark_results(
    check_ids_with_findings: set[str],
    checks_run: set[str],
) -> list[dict]:
    """Evaluate benchmark items against scan results.

    Returns a list of dicts with keys: id, title, section, status, level.
    Status is 'pass', 'fail', 'warn', or 'skip'.
    """
    results = []
    for item in JUPYTERHUB_BENCHMARK:
        relevant_run = [cid for cid in item.check_ids if cid in checks_run]
        if not relevant_run:
            status = "skip"
        elif any(cid in check_ids_with_findings for cid in item.check_ids):
            status = "fail"
        else:
            status = "pass"

        results.append({
            "id": item.id,
            "title": item.title,
            "section": item.section,
            "status": status,
            "level": item.level,
        })
    return results

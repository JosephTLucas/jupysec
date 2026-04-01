# jupysec

Adversarial security assessment for JupyterHub deployments.

jupysec models real attack chains against JupyterHub -- not just configuration compliance, but what an attacker actually does after landing on a deployment. It speaks the Jupyter REST and WebSocket kernel protocols natively, executes probes from inside user kernels to test isolation boundaries, and audits the full stack from Hub config to Kubernetes pod security.

## Install

```bash
uv pip install jupysec

# With Kubernetes checks:
uv pip install 'jupysec[kubernetes]'
```

## Modes

**External (closed-box)** -- Point at a Hub URL with an API token. Probes APIs, tests auth boundaries, attempts privilege escalation, verifies user isolation over HTTP and WebSocket, and executes SSRF probes from inside kernels.

**Internal (open-box)** -- Runs on the Hub host or in the cluster. Parses `jupyterhub_config.py` via AST (no exec), inspects Kubernetes resources, and audits spawner/authenticator/proxy settings.

## Usage

```bash
# External scan
jupysec scan --target https://hub.example.com --token <api-token> --mode external

# Internal scan of a config file
jupysec scan --config /etc/jupyterhub/jupyterhub_config.py --mode internal

# Full scan (both modes)
jupysec scan --target https://hub.example.com --config jupyterhub_config.py --mode full

# Kubernetes-aware internal scan
jupysec scan --kubeconfig ~/.kube/config --namespace jhub --mode internal

# Output formats: text (default), json, html, sarif
jupysec scan --config jupyterhub_config.py -m internal -o report.html
jupysec scan --config jupyterhub_config.py -m internal -o results.sarif

# Re-render a report from saved JSON
jupysec report --input results.json --format html --output report.html

# List checks / browse benchmark
jupysec checks
jupysec benchmark list
jupysec benchmark show JHB-1.1
```

## Checks

39 checks organized by what they test and how.

### Attack simulation (`attack/*`)

These model real attacker behavior -- they don't just check config flags, they try the attack.

| Check | What it does |
|-------|-------------|
| `attack/cloud-metadata-ssrf` | Executes code in a kernel to reach AWS/GCP/Azure metadata (169.254.169.254). The #1 real-world Jupyter exploit -- leads to cloud IAM credential theft. |
| `attack/internal-service-ssrf` | From inside a kernel, probes for Kubernetes API, Hub internal API, and proxy API access that should be blocked by NetworkPolicies. |
| `attack/token-blast-radius` | Determines what a compromised notebook's `JUPYTERHUB_API_TOKEN` can actually do: list users, create tokens for persistence, start other users' servers, read proxy topology. |
| `attack/env-token-leak` | Enumerates all sensitive environment variables (tokens, secrets, passwords) visible inside a user kernel. |
| `attack/container-escape` | Inspects running user pods for escape vectors beyond `privileged: true`: hostPath mounts, docker socket, dangerous capabilities, hostPID/hostNetwork, SA token auto-mount. |
| `attack/direct-server-bypass` | Checks if user notebook servers are directly reachable, bypassing Hub proxy authentication entirely. |
| `attack/shared-storage` | Flags shared writable storage (RWX PVCs, NFS) that lets one user inject code into another user's notebooks. |

### External probes

| Check | What it does |
|-------|-------------|
| `auth/token-required` | Attempts unauthenticated access to Hub API endpoints |
| `auth/admin-escalation` | Attempts CVE-2024-41942 privilege escalation (PATCH self to admin) |
| `auth/cookie-flags` | Checks Secure, HttpOnly, SameSite on session cookies |
| `network/tls-config` | TLS version, cipher strength, certificate validity |
| `network/cors-policy` | Tests CORS with an attacker-controlled Origin |
| `network/csp-policy` | Content-Security-Policy presence and strength |
| `api/endpoint-enum` | Probes all known Hub API endpoints without auth |
| `api/permission-probe` | Tests which admin endpoints a given token can access |
| `api/xsrf-enforcement` | Sends state-changing requests without XSRF token |
| `api/info-disclosure` | Checks if `/hub/api/` leaks version info |
| `api/version-headers` | Server/X-Powered-By headers leaking version strings |
| `ws/kernel-auth` | Attempts unauthenticated WebSocket connections to kernel endpoints (CVE-2024-28179 pattern) |
| `ws/kernel-isolation` | Attempts to connect to another user's kernel using the current user's token |
| `isolation/cross-user` | Tries to access another user's REST API (files, kernels, terminals) |
| `isolation/proxy-routes` | Audits proxy routing table for suspicious targets |

### Internal audits

| Check | What it does |
|-------|-------------|
| `config/cookie-secret` | Cookie secret explicitly configured (not auto-generated) |
| `config/proxy-token` | Proxy auth token explicitly configured |
| `config/allow-root` | Hub not configured to run as root |
| `config/bind-address` | Hub not bound to 0.0.0.0 / :: |
| `config/authenticator-type` | Not using DummyAuthenticator / NullAuthenticator |
| `config/authenticator-settings` | OAuth secrets not hardcoded, allow_all not true |
| `config/admin-users` | Admin list is small, admin_access is off |
| `config/spawner-limits` | Memory and CPU limits set on spawner |
| `config/spawner-privileged` | No privileged containers, no uid=0 |
| `k8s/network-policy` | NetworkPolicies exist with egress restrictions |
| `k8s/pod-security` | Pod Security Standards enforce label on namespace |
| `k8s/rbac-minimal` | ServiceAccounts not bound to cluster-admin |
| `k8s/secrets-security` | Secrets not stored in plaintext annotations |
| `k8s/resource-limits` | Running user pods have resource limits |
| `supply/cve-check` | Installed versions checked against 8 known Jupyter CVEs |
| `supply/extensions` | Server extensions audited for known risks |
| `supply/image-trust` | Container images pinned, allowlisted |

## Security Benchmark

26-item JupyterHub Security Benchmark (JHB-1.1 through JHB-7.3) modeled after CIS Benchmarks. Covers authentication, transport security, API security, user isolation, deployment configuration, Kubernetes, and supply chain. Each scan produces a score.

## Design

- **AST-based config parsing** -- `jupyterhub_config.py` is parsed with `ast` to extract `c.Class.trait = value` assignments. No exec.
- **Kernel code execution for SSRF probes** -- The `attack/*` checks open WebSocket connections to kernels using the Jupyter wire protocol and execute probe code to test isolation from the attacker's perspective.
- **Async engine** -- All network checks run concurrently via `httpx.AsyncClient` and `websockets`. Configurable concurrency.
- **Auto-discovery** -- Checks are auto-discovered by walking the `jupysec.checks` package. Adding a check = adding a file.
- **CI-friendly** -- Exit code 1 when critical/high findings exist. SARIF output for GitHub Advanced Security / GitLab SAST.

## Development

```bash
git clone https://github.com/JosephTLucas/jupysec.git
cd jupysec
uv venv && uv pip install -e ".[dev]"
pytest
```

## License

BSD-3-Clause

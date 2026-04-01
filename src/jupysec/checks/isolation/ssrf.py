"""SSRF checks: can user notebooks reach cloud metadata and internal services?

This is the #1 real-world Jupyter attack vector. A legitimate user (or attacker
with notebook access) can make HTTP requests from kernel code to:
  - Cloud metadata services (169.254.169.254) to steal IAM credentials
  - Internal cluster services (Hub DB, K8s API) that should be unreachable
  - Other user servers directly (bypassing Hub proxy auth)

We test this both externally (by executing code via the Jupyter API if we have
a token) and internally (by inspecting NetworkPolicies and egress rules).
"""

from __future__ import annotations

import httpx

from jupysec.checks.base import BaseCheck
from jupysec.core.finding import Category, Finding, Severity
from jupysec.core.target import Target
from jupysec.utils.http import client_for


METADATA_ENDPOINTS = [
    ("AWS", "http://169.254.169.254/latest/meta-data/"),
    ("GCP", "http://metadata.google.internal/computeMetadata/v1/"),
    ("Azure", "http://169.254.169.254/metadata/instance?api-version=2021-02-01"),
]

INTERNAL_SERVICES = [
    ("Kubernetes API", "https://kubernetes.default.svc/api"),
    ("Hub internal API", "http://hub:8081/hub/api/"),
    ("Hub DB (postgres)", "hub-db:5432"),
]


class CloudMetadataSSRFCheck(BaseCheck):
    """Attempt to reach cloud metadata from a user's kernel.

    This models the exact attack: from a compromised or malicious notebook,
    make HTTP requests to the cloud metadata service to steal IAM credentials
    that grant access to the cloud account.
    """

    id = "attack/cloud-metadata-ssrf"
    title = "User notebooks can reach cloud metadata service"
    severity = Severity.CRITICAL
    category = Category.ISOLATION
    mode = "external"
    cwe = "CWE-918"
    references = [
        "https://z2jh.jupyter.org/en/stable/administrator/security.html",
        "https://docs.aws.amazon.com/AWSEC2/latest/UserGuide/instancedata-data-retrieval.html",
    ]

    def prerequisites_met(self, target: Target) -> bool:
        return target.has_external and target.token is not None

    async def run(self, target: Target) -> list[Finding]:
        findings: list[Finding] = []

        # We need a running kernel to execute code. Start by finding one
        # or creating one via the user's server.
        kernel_id = await self._get_or_start_kernel(target)
        if not kernel_id:
            return findings

        for cloud, url in METADATA_ENDPOINTS:
            code = self._build_probe_code(cloud, url)
            result = await self._execute_in_kernel(target, kernel_id, code)

            if result and "SSRF_REACHABLE" in result:
                response_preview = result.split("SSRF_REACHABLE:")[-1][:200]
                findings.append(Finding(
                    check_id=self.id,
                    severity=Severity.CRITICAL,
                    title=f"Cloud metadata reachable from notebook ({cloud})",
                    description=(
                        f"Code executed in a user's Jupyter kernel successfully reached "
                        f"the {cloud} metadata service at {url}. An attacker with notebook "
                        f"access can steal cloud IAM credentials and escalate to cloud "
                        f"account-level access."
                    ),
                    evidence=f"Kernel HTTP request to {url} returned: {response_preview}",
                    remediation=(
                        f"Block egress to 169.254.169.254 from user pods. "
                        f"For Kubernetes: add a NetworkPolicy denying egress to 169.254.169.254/32. "
                        f"The Z2JH Helm chart supports this via "
                        f"singleuser.networkPolicy.egressAllowRules.privateIPs=false. "
                        f"For AWS specifically, also consider IMDSv2 with hop limit=1."
                    ),
                    cwe=self.cwe,
                    references=self.references,
                    target_component="kubernetes",
                ))

        return findings

    def _build_probe_code(self, cloud: str, url: str) -> str:
        headers = ""
        if cloud == "GCP":
            headers = ", headers={'Metadata-Flavor': 'Google'}"
        elif cloud == "Azure":
            headers = ", headers={'Metadata': 'true'}"

        return (
            "import urllib.request, urllib.error\n"
            "try:\n"
            f"    req = urllib.request.Request('{url}'{headers})\n"
            "    resp = urllib.request.urlopen(req, timeout=3)\n"
            "    body = resp.read().decode('utf-8', errors='replace')[:500]\n"
            "    print(f'SSRF_REACHABLE:{body}')\n"
            "except Exception as e:\n"
            "    print(f'SSRF_BLOCKED:{e}')\n"
        )

    async def _get_or_start_kernel(self, target: Target) -> str | None:
        """Find an existing kernel or start one via the user's server API."""
        async with client_for(target) as client:
            # Find current user's server
            try:
                resp = await client.get("/hub/api/user")
                if resp.status_code != 200:
                    return None
                user = resp.json()
                username = user.get("name", "")
                if not user.get("server") and not user.get("servers"):
                    return None
            except (httpx.HTTPError, ValueError):
                return None

            # List existing kernels
            try:
                resp = await client.get(f"/user/{username}/api/kernels")
                if resp.status_code == 200:
                    kernels = resp.json()
                    if kernels:
                        return kernels[0]["id"]
            except (httpx.HTTPError, ValueError):
                pass

            # Start a new kernel
            try:
                resp = await client.post(
                    f"/user/{username}/api/kernels",
                    json={"name": "python3"},
                )
                if resp.status_code in (200, 201):
                    return resp.json().get("id")
            except (httpx.HTTPError, ValueError):
                pass

        return None

    async def _execute_in_kernel(
        self, target: Target, kernel_id: str, code: str
    ) -> str | None:
        """Execute code in a kernel via the REST API and collect output."""
        import json
        import uuid

        from jupysec.utils.websocket import ws_url_for, try_ws_connect

        async with client_for(target) as client:
            try:
                resp = await client.get("/hub/api/user")
                username = resp.json().get("name", "")
            except Exception:
                return None

        ws_path = f"/user/{username}/api/kernels/{kernel_id}/channels"
        ws_url = ws_url_for(target.base_url, ws_path)

        import ssl as _ssl
        import websockets.asyncio.client

        headers = {}
        if target.token:
            headers["Authorization"] = f"token {target.token}"

        ssl_context: _ssl.SSLContext | None = None
        if ws_url.startswith("wss://"):
            ssl_context = _ssl.create_default_context()
            if not target.verify_ssl:
                ssl_context.check_hostname = False
                ssl_context.verify_mode = _ssl.CERT_NONE

        msg_id = str(uuid.uuid4())
        execute_msg = {
            "header": {
                "msg_id": msg_id,
                "msg_type": "execute_request",
                "username": "",
                "session": str(uuid.uuid4()),
                "version": "5.3",
            },
            "parent_header": {},
            "metadata": {},
            "content": {
                "code": code,
                "silent": False,
                "store_history": False,
                "user_expressions": {},
                "allow_stdin": False,
                "stop_on_error": True,
            },
            "channel": "shell",
        }

        output_lines: list[str] = []
        try:
            async with websockets.asyncio.client.connect(
                ws_url,
                additional_headers=headers,
                ssl=ssl_context,
                open_timeout=10,
                close_timeout=5,
            ) as ws:
                await ws.send(json.dumps(execute_msg))

                import asyncio

                deadline = asyncio.get_event_loop().time() + 15
                while asyncio.get_event_loop().time() < deadline:
                    try:
                        raw = await asyncio.wait_for(ws.recv(), timeout=5)
                        msg = json.loads(raw)
                        msg_type = msg.get("msg_type") or msg.get("header", {}).get("msg_type", "")
                        parent_id = msg.get("parent_header", {}).get("msg_id", "")

                        if parent_id != msg_id:
                            continue

                        if msg_type == "stream":
                            output_lines.append(msg["content"].get("text", ""))
                        elif msg_type == "execute_result":
                            output_lines.append(
                                msg["content"].get("data", {}).get("text/plain", "")
                            )
                        elif msg_type in ("execute_reply", "error"):
                            break
                    except asyncio.TimeoutError:
                        break

        except Exception:
            return None

        return "\n".join(output_lines) if output_lines else None


class InternalServiceSSRFCheck(BaseCheck):
    """Check if user notebooks can reach internal cluster services.

    Models the attack where a user's kernel makes requests to internal
    services that should be isolated by NetworkPolicies.
    """

    id = "attack/internal-service-ssrf"
    title = "User notebooks can reach internal cluster services"
    severity = Severity.HIGH
    category = Category.ISOLATION
    mode = "external"
    cwe = "CWE-918"
    references = [
        "https://z2jh.jupyter.org/en/stable/administrator/security.html",
    ]

    def prerequisites_met(self, target: Target) -> bool:
        return target.has_external and target.token is not None

    async def run(self, target: Target) -> list[Finding]:
        # Reuse the SSRF check's kernel infrastructure
        ssrf_check = CloudMetadataSSRFCheck()
        kernel_id = await ssrf_check._get_or_start_kernel(target)
        if not kernel_id:
            return []

        findings: list[Finding] = []

        # Probe K8s API from inside the kernel
        k8s_code = (
            "import urllib.request, urllib.error, ssl\n"
            "ctx = ssl.create_default_context()\n"
            "ctx.check_hostname = False\n"
            "ctx.verify_mode = ssl.CERT_NONE\n"
            "try:\n"
            "    resp = urllib.request.urlopen('https://kubernetes.default.svc/api', timeout=3, context=ctx)\n"
            "    print(f'SSRF_REACHABLE:{resp.read().decode()[:300]}')\n"
            "except Exception as e:\n"
            "    print(f'SSRF_BLOCKED:{e}')\n"
        )

        result = await ssrf_check._execute_in_kernel(target, kernel_id, k8s_code)
        if result and "SSRF_REACHABLE" in result:
            findings.append(Finding(
                check_id=self.id,
                severity=Severity.HIGH,
                title="Kubernetes API reachable from notebook",
                description=(
                    "Code in a user's kernel can reach the Kubernetes API server. "
                    "If the pod's service account has any permissions, this enables "
                    "cluster reconnaissance or resource manipulation."
                ),
                evidence=result[:300],
                remediation=(
                    "Add a NetworkPolicy blocking egress to the K8s API server, "
                    "or ensure the pod's service account has no permissions."
                ),
                cwe=self.cwe,
                references=self.references,
                target_component="kubernetes",
            ))

        # Probe for Hub internal API
        hub_code = (
            "import urllib.request, urllib.error\n"
            "for url in ['http://hub:8081/hub/api/', 'http://hub:8081/', 'http://proxy-api:8001/api/routes']:\n"
            "    try:\n"
            "        resp = urllib.request.urlopen(url, timeout=3)\n"
            "        print(f'SSRF_REACHABLE:{url}:{resp.read().decode()[:200]}')\n"
            "    except Exception as e:\n"
            "        print(f'SSRF_BLOCKED:{url}:{e}')\n"
        )

        result = await ssrf_check._execute_in_kernel(target, kernel_id, hub_code)
        if result and "SSRF_REACHABLE" in result:
            findings.append(Finding(
                check_id=self.id,
                severity=Severity.HIGH,
                title="Hub internal API reachable from notebook",
                description=(
                    "Code in a user's kernel can reach the Hub's internal API. "
                    "This may allow bypassing authentication or accessing admin endpoints "
                    "directly."
                ),
                evidence=result[:300],
                remediation=(
                    "Add a NetworkPolicy blocking egress from user pods to the Hub pod. "
                    "Z2JH's default NetworkPolicies should handle this."
                ),
                cwe=self.cwe,
                references=self.references,
                target_component="hub",
            ))

        return findings

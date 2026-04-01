"""TLS configuration assessment."""

from __future__ import annotations

import ssl
from urllib.parse import urlparse

from jupysec.checks.base import BaseCheck
from jupysec.core.finding import Category, Finding, Severity
from jupysec.core.target import Target

WEAK_PROTOCOLS = {
    ssl.TLSVersion.SSLv3: "SSLv3",
    ssl.TLSVersion.TLSv1: "TLS 1.0",
    ssl.TLSVersion.TLSv1_1: "TLS 1.1",
}


class TLSConfigCheck(BaseCheck):
    id = "network/tls-config"
    title = "TLS configuration is secure"
    severity = Severity.HIGH
    category = Category.NETWORK
    mode = "external"
    cwe = "CWE-326"
    references = [
        "https://jupyterhub.readthedocs.io/en/stable/tutorial/getting-started/security-basics.html",
    ]

    def prerequisites_met(self, target: Target) -> bool:
        return target.has_external and bool(target.url and target.url.startswith("https"))

    async def run(self, target: Target) -> list[Finding]:
        findings: list[Finding] = []
        parsed = urlparse(target.url)
        host = parsed.hostname or ""
        port = parsed.port or 443

        ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE

        import asyncio

        try:
            reader, writer = await asyncio.wait_for(
                asyncio.open_connection(host, port, ssl=ctx),
                timeout=target.timeout,
            )
        except Exception as exc:
            findings.append(Finding(
                check_id=self.id,
                severity=Severity.HIGH,
                title="TLS connection failed",
                description=f"Could not establish TLS connection to {host}:{port}: {exc}",
                remediation="Ensure the target is serving HTTPS with a valid TLS configuration.",
                cwe=self.cwe,
                references=self.references,
                target_component="proxy",
            ))
            return findings

        ssl_obj = writer.get_extra_info("ssl_object")
        if ssl_obj:
            version_str = ssl_obj.version()
            if version_str and version_str in ("SSLv3", "TLSv1", "TLSv1.0", "TLSv1.1"):
                findings.append(Finding(
                    check_id=self.id,
                    severity=Severity.HIGH,
                    title=f"Weak TLS version: {version_str}",
                    description=(
                        f"The server negotiated {version_str}, which has known vulnerabilities. "
                        "TLS 1.2 or 1.3 should be the minimum."
                    ),
                    evidence=f"Negotiated protocol: {version_str}",
                    remediation="Configure the server or reverse proxy to support only TLS 1.2+.",
                    cwe=self.cwe,
                    references=self.references,
                    target_component="proxy",
                ))

            cipher = ssl_obj.cipher()
            if cipher:
                cipher_name, _, bits = cipher
                if bits and bits < 128:
                    findings.append(Finding(
                        check_id=self.id,
                        severity=Severity.HIGH,
                        title=f"Weak cipher: {cipher_name} ({bits}-bit)",
                        description=f"The negotiated cipher {cipher_name} uses only {bits} bits.",
                        evidence=f"Cipher: {cipher_name}, {bits} bits",
                        remediation="Restrict cipher suites to AES-128+ or ChaCha20.",
                        cwe=self.cwe,
                        references=self.references,
                        target_component="proxy",
                    ))

            try:
                cert_der = ssl_obj.getpeercert(binary_form=True)
                if cert_der:
                    from cryptography import x509

                    cert = x509.load_der_x509_certificate(cert_der)
                    from datetime import datetime, timezone

                    now = datetime.now(timezone.utc)
                    if cert.not_valid_after_utc < now:
                        findings.append(Finding(
                            check_id=self.id,
                            severity=Severity.HIGH,
                            title="TLS certificate expired",
                            description=f"Certificate expired on {cert.not_valid_after_utc.isoformat()}.",
                            evidence=f"notAfter: {cert.not_valid_after_utc.isoformat()}",
                            remediation="Renew the TLS certificate.",
                            cwe="CWE-295",
                            references=self.references,
                            target_component="proxy",
                        ))
            except Exception:
                pass

        writer.close()
        return findings

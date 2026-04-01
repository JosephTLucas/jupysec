"""Known Jupyter ecosystem CVEs with affected version ranges.

Each entry maps a package name to a list of known vulnerabilities.
Version ranges use packaging.version for comparison.
"""

from __future__ import annotations

from dataclasses import dataclass


@dataclass
class KnownCVE:
    cve_id: str
    package: str
    affected: str  # Human-readable version range
    fixed_in: str
    severity: str  # critical, high, medium, low
    description: str
    url: str

    def affects(self, installed_version: str) -> bool:
        """Check if an installed version is affected by this CVE."""
        from packaging.version import Version, InvalidVersion

        try:
            ver = Version(installed_version)
        except InvalidVersion:
            return False

        try:
            fix = Version(self.fixed_in)
            return ver < fix
        except InvalidVersion:
            return False


JUPYTER_CVES: list[KnownCVE] = [
    KnownCVE(
        cve_id="CVE-2024-41942",
        package="jupyterhub",
        affected="< 4.1.6, < 5.1.0",
        fixed_in="4.1.6",
        severity="high",
        description=(
            "Users with admin:users scope can escalate to full admin. "
            "Fixed in JupyterHub 4.1.6 and 5.1.0."
        ),
        url="https://nvd.nist.gov/vuln/detail/CVE-2024-41942",
    ),
    KnownCVE(
        cve_id="CVE-2024-28233",
        package="jupyterhub",
        affected="< 4.1.0",
        fixed_in="4.1.0",
        severity="high",
        description=(
            "XSS on subdomains affecting single-origin JupyterHub deployments."
        ),
        url="https://nvd.nist.gov/vuln/detail/CVE-2024-28233",
    ),
    KnownCVE(
        cve_id="CVE-2024-35225",
        package="jupyter-server-proxy",
        affected="3.x < 3.2.4, 4.x < 4.2.0",
        fixed_in="3.2.4",
        severity="critical",
        description=(
            "Reflected XSS in Jupyter Server Proxy via /proxy endpoint "
            "with unsanitized host values."
        ),
        url="https://nvd.nist.gov/vuln/detail/CVE-2024-35225",
    ),
    KnownCVE(
        cve_id="CVE-2024-28179",
        package="jupyter-server-proxy",
        affected="< 3.2.3, 4.x < 4.1.1",
        fixed_in="3.2.3",
        severity="critical",
        description=(
            "Unauthenticated WebSocket proxy access allowing remote code execution."
        ),
        url="https://nvd.nist.gov/vuln/detail/CVE-2024-28179",
    ),
    KnownCVE(
        cve_id="CVE-2021-41194",
        package="jupyterhub-firstuseauthenticator",
        affected="< 1.0.0",
        fixed_in="1.0.0",
        severity="critical",
        description=(
            "Account takeover when create_users=True and username is guessable."
        ),
        url="https://nvd.nist.gov/vuln/detail/CVE-2021-41194",
    ),
    KnownCVE(
        cve_id="CVE-2025-30167",
        package="jupyter-core",
        affected="< 5.8.0",
        fixed_in="5.8.0",
        severity="high",
        description=(
            "Shared PROGRAMDATA directory on Windows allows unauthorized config modification."
        ),
        url="https://nvd.nist.gov/vuln/detail/CVE-2025-30167",
    ),
    KnownCVE(
        cve_id="CVE-2025-53000",
        package="nbconvert",
        affected="< 7.17.0",
        fixed_in="7.17.0",
        severity="high",
        description=(
            "RCE via SVG output during PDF conversion on Windows."
        ),
        url="https://nvd.nist.gov/vuln/detail/CVE-2025-53000",
    ),
    KnownCVE(
        cve_id="CVE-2024-22421",
        package="jupyter-server",
        affected="< 2.12.1",
        fixed_in="2.12.1",
        severity="high",
        description=(
            "Authentication bypass via crafted URL allowing unauthorized API access."
        ),
        url="https://nvd.nist.gov/vuln/detail/CVE-2024-22421",
    ),
]

"""Target model describing a JupyterHub deployment to assess."""

from __future__ import annotations

from pathlib import Path

from pydantic import BaseModel


class Target(BaseModel):
    """Represents a JupyterHub deployment to scan."""

    url: str | None = None
    token: str | None = None
    username: str | None = None
    password: str | None = None
    config_path: Path | None = None
    kubeconfig: Path | None = None
    namespace: str | None = None
    verify_ssl: bool = True
    timeout: float = 30.0

    @property
    def has_external(self) -> bool:
        return self.url is not None

    @property
    def has_internal(self) -> bool:
        return self.config_path is not None or self.kubeconfig is not None

    @property
    def base_url(self) -> str:
        """URL normalized with trailing slash."""
        if not self.url:
            return ""
        return self.url.rstrip("/")

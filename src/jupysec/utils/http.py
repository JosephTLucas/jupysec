"""Async HTTP client wrapper with JupyterHub auth handling."""

from __future__ import annotations

from contextlib import asynccontextmanager
from typing import AsyncIterator

import httpx

from jupysec.core.target import Target


@asynccontextmanager
async def client_for(target: Target) -> AsyncIterator[httpx.AsyncClient]:
    """Yield an httpx.AsyncClient configured for the target."""
    headers: dict[str, str] = {}
    if target.token:
        headers["Authorization"] = f"token {target.token}"

    async with httpx.AsyncClient(
        base_url=target.base_url,
        headers=headers,
        verify=target.verify_ssl,
        timeout=target.timeout,
        follow_redirects=True,
    ) as client:
        yield client

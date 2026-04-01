"""WebSocket utilities for probing Jupyter kernel endpoints."""

from __future__ import annotations

import json
import ssl as _ssl
from urllib.parse import urlparse

import websockets
import websockets.asyncio.client


def ws_url_for(base_http_url: str, path: str) -> str:
    """Convert an HTTP(S) base URL to a WebSocket URL with the given path."""
    parsed = urlparse(base_http_url)
    scheme = "wss" if parsed.scheme == "https" else "ws"
    return f"{scheme}://{parsed.netloc}{path}"


async def try_ws_connect(
    url: str,
    *,
    token: str | None = None,
    verify_ssl: bool = True,
    timeout: float = 10.0,
) -> tuple[bool, str]:
    """Attempt a WebSocket connection. Returns (connected, detail_message)."""
    headers: dict[str, str] = {}
    if token:
        headers["Authorization"] = f"token {token}"

    ssl_context: _ssl.SSLContext | None = None
    if url.startswith("wss://"):
        ssl_context = _ssl.create_default_context()
        if not verify_ssl:
            ssl_context.check_hostname = False
            ssl_context.verify_mode = _ssl.CERT_NONE

    try:
        async with websockets.asyncio.client.connect(
            url,
            additional_headers=headers,
            ssl=ssl_context,
            open_timeout=timeout,
            close_timeout=5,
        ) as ws:
            return True, f"Connected, protocol={ws.protocol}"
    except websockets.exceptions.InvalidStatusCode as exc:
        return False, f"Rejected: HTTP {exc.status_code}"
    except Exception as exc:
        return False, f"Error: {type(exc).__name__}: {exc}"

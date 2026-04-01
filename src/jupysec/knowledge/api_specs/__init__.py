"""Bundled knowledge of JupyterHub and Jupyter Server API endpoints."""

from __future__ import annotations

HUB_API_ENDPOINTS: list[dict[str, str]] = [
    {"method": "GET", "path": "/hub/api/", "scope": "read:hub", "desc": "Hub version info"},
    {"method": "GET", "path": "/hub/api/info", "scope": "read:hub", "desc": "Detailed hub info"},
    {"method": "GET", "path": "/hub/api/users", "scope": "read:users", "desc": "List users"},
    {"method": "POST", "path": "/hub/api/users", "scope": "admin:users", "desc": "Create users"},
    {"method": "GET", "path": "/hub/api/users/{name}", "scope": "read:users:name", "desc": "Get user"},
    {"method": "DELETE", "path": "/hub/api/users/{name}", "scope": "delete:users", "desc": "Delete user"},
    {"method": "POST", "path": "/hub/api/users/{name}/server", "scope": "servers", "desc": "Start server"},
    {"method": "DELETE", "path": "/hub/api/users/{name}/server", "scope": "servers", "desc": "Stop server"},
    {"method": "GET", "path": "/hub/api/users/{name}/tokens", "scope": "read:tokens", "desc": "List tokens"},
    {"method": "POST", "path": "/hub/api/users/{name}/tokens", "scope": "tokens", "desc": "Create token"},
    {"method": "GET", "path": "/hub/api/services", "scope": "read:services", "desc": "List services"},
    {"method": "GET", "path": "/hub/api/groups", "scope": "read:groups", "desc": "List groups"},
    {"method": "GET", "path": "/hub/api/proxy", "scope": "read:proxy", "desc": "Proxy routes"},
    {"method": "POST", "path": "/hub/api/shutdown", "scope": "shutdown", "desc": "Shutdown hub"},
    {"method": "POST", "path": "/hub/api/authorizations/token/{token}", "scope": "read:hub", "desc": "Check token"},
]

JUPYTER_SERVER_ENDPOINTS: list[dict[str, str]] = [
    {"method": "GET", "path": "/api", "scope": "read", "desc": "Server info"},
    {"method": "GET", "path": "/api/kernels", "scope": "read", "desc": "List kernels"},
    {"method": "POST", "path": "/api/kernels", "scope": "write", "desc": "Start kernel"},
    {"method": "GET", "path": "/api/sessions", "scope": "read", "desc": "List sessions"},
    {"method": "GET", "path": "/api/contents/", "scope": "read", "desc": "List files"},
    {"method": "GET", "path": "/api/terminals", "scope": "read", "desc": "List terminals"},
    {"method": "POST", "path": "/api/terminals", "scope": "write", "desc": "Create terminal"},
    {"method": "GET", "path": "/api/config/ServerApp", "scope": "read", "desc": "Server config"},
]

STATE_CHANGING_METHODS = {"POST", "PUT", "PATCH", "DELETE"}

"""Kubernetes client wrapper with auto-detection of in-cluster vs kubeconfig."""

from __future__ import annotations

from contextlib import contextmanager
from pathlib import Path
from typing import Iterator


def _load_k8s():
    """Import and return the kubernetes client module, raising ImportError if missing."""
    try:
        from kubernetes import client, config  # type: ignore[import-untyped]

        return client, config
    except ImportError:
        raise ImportError(
            "The 'kubernetes' package is required for Kubernetes checks. "
            "Install it with: uv pip install 'jupysec[kubernetes]'"
        )


@contextmanager
def k8s_client(kubeconfig: Path | None = None) -> Iterator:
    """Yield a kubernetes CoreV1Api / RbacV1Api-ready state.

    Tries in order: explicit kubeconfig, in-cluster config, default kubeconfig.
    """
    client, config = _load_k8s()

    if kubeconfig and kubeconfig.exists():
        config.load_kube_config(str(kubeconfig))
    else:
        try:
            config.load_incluster_config()
        except config.ConfigException:
            config.load_kube_config()

    yield client

"""Tests for internal config checks against sample configs."""

import asyncio
import textwrap
from pathlib import Path

import pytest

from jupysec.core.target import Target


def _run(coro):
    return asyncio.get_event_loop().run_until_complete(coro)


def _make_target(tmp_path: Path, config_content: str) -> Target:
    cfg = tmp_path / "jupyterhub_config.py"
    cfg.write_text(textwrap.dedent(config_content))
    return Target(config_path=cfg)


@pytest.mark.asyncio
async def test_cookie_secret_missing(tmp_path: Path):
    from jupysec.checks.config.hub_config import CookieSecretCheck

    target = _make_target(tmp_path, "c.JupyterHub.ip = '127.0.0.1'\n")
    findings = await CookieSecretCheck().run(target)
    assert len(findings) == 1
    assert "cookie_secret" in findings[0].title.lower() or "cookie secret" in findings[0].title.lower()


@pytest.mark.asyncio
async def test_cookie_secret_configured(tmp_path: Path):
    from jupysec.checks.config.hub_config import CookieSecretCheck

    target = _make_target(tmp_path, "c.JupyterHub.cookie_secret_file = '/srv/secret'\n")
    findings = await CookieSecretCheck().run(target)
    assert len(findings) == 0


@pytest.mark.asyncio
async def test_authenticator_dummy(tmp_path: Path):
    from jupysec.checks.config.authenticator_config import AuthenticatorTypeCheck

    target = _make_target(tmp_path, "c.JupyterHub.authenticator_class = 'DummyAuthenticator'\n")
    findings = await AuthenticatorTypeCheck().run(target)
    assert len(findings) == 1
    assert findings[0].severity.value == "critical"


@pytest.mark.asyncio
async def test_authenticator_oauth(tmp_path: Path):
    from jupysec.checks.config.authenticator_config import AuthenticatorTypeCheck

    target = _make_target(tmp_path, "c.JupyterHub.authenticator_class = 'oauthenticator.github.GitHubOAuthenticator'\n")
    findings = await AuthenticatorTypeCheck().run(target)
    assert len(findings) == 0


@pytest.mark.asyncio
async def test_spawner_privileged(tmp_path: Path):
    from jupysec.checks.config.spawner_config import SpawnerPrivilegedCheck

    target = _make_target(tmp_path, "c.KubeSpawner.privileged = True\n")
    findings = await SpawnerPrivilegedCheck().run(target)
    assert len(findings) == 1
    assert findings[0].severity.value == "critical"


@pytest.mark.asyncio
async def test_spawner_not_privileged(tmp_path: Path):
    from jupysec.checks.config.spawner_config import SpawnerPrivilegedCheck

    target = _make_target(tmp_path, "c.KubeSpawner.privileged = False\n")
    findings = await SpawnerPrivilegedCheck().run(target)
    assert len(findings) == 0


@pytest.mark.asyncio
async def test_allow_root_true(tmp_path: Path):
    from jupysec.checks.config.hub_config import AllowRootCheck

    target = _make_target(tmp_path, "c.JupyterHub.allow_root = True\n")
    findings = await AllowRootCheck().run(target)
    assert len(findings) == 1


@pytest.mark.asyncio
async def test_bind_address_all_interfaces(tmp_path: Path):
    from jupysec.checks.config.proxy_config import BindAddressCheck

    target = _make_target(tmp_path, "c.JupyterHub.ip = '0.0.0.0'\n")
    findings = await BindAddressCheck().run(target)
    assert any("all interfaces" in f.title.lower() or "bound to all" in f.title.lower() for f in findings)


@pytest.mark.asyncio
async def test_oauth_secret_hardcoded(tmp_path: Path):
    from jupysec.checks.config.authenticator_config import AuthenticatorSettingsCheck

    target = _make_target(tmp_path, "c.OAuthenticator.client_secret = 'supersecret123'\n")
    findings = await AuthenticatorSettingsCheck().run(target)
    assert any("hardcoded" in f.title.lower() for f in findings)

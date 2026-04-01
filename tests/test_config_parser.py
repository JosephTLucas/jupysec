"""Tests for the AST-based jupyterhub_config.py parser."""

import textwrap
from pathlib import Path

from jupysec.utils.config_parser import parse_config


def test_basic_string_assignment(tmp_path: Path):
    cfg = tmp_path / "jupyterhub_config.py"
    cfg.write_text("c.JupyterHub.authenticator_class = 'DummyAuthenticator'\n")
    result = parse_config(cfg)
    assert result.get("JupyterHub", "authenticator_class") == "DummyAuthenticator"


def test_boolean_and_numeric(tmp_path: Path):
    cfg = tmp_path / "jupyterhub_config.py"
    cfg.write_text(textwrap.dedent("""\
        c.JupyterHub.allow_root = True
        c.KubeSpawner.cpu_limit = 2
        c.KubeSpawner.mem_limit = '4G'
    """))
    result = parse_config(cfg)
    assert result.get("JupyterHub", "allow_root") is True
    assert result.get("KubeSpawner", "cpu_limit") == 2
    assert result.get("KubeSpawner", "mem_limit") == "4G"


def test_list_assignment(tmp_path: Path):
    cfg = tmp_path / "jupyterhub_config.py"
    cfg.write_text("c.Authenticator.admin_users = ['alice', 'bob']\n")
    result = parse_config(cfg)
    assert result.get("Authenticator", "admin_users") == ["alice", "bob"]


def test_unresolved_dynamic_value(tmp_path: Path):
    cfg = tmp_path / "jupyterhub_config.py"
    cfg.write_text("c.JupyterHub.cookie_secret_file = os.environ.get('SECRET')\n")
    result = parse_config(cfg)
    assert result.get("JupyterHub", "cookie_secret_file") is None
    assert len(result.unresolved) == 1
    assert result.unresolved[0].classname == "JupyterHub"
    assert result.unresolved[0].trait == "cookie_secret_file"


def test_missing_file():
    result = parse_config("/nonexistent/path.py")
    assert len(result.errors) > 0


def test_syntax_error(tmp_path: Path):
    cfg = tmp_path / "jupyterhub_config.py"
    cfg.write_text("c.JupyterHub. = broken\n")
    result = parse_config(cfg)
    assert len(result.errors) > 0


def test_get_class_settings(tmp_path: Path):
    cfg = tmp_path / "jupyterhub_config.py"
    cfg.write_text(textwrap.dedent("""\
        c.KubeSpawner.cpu_limit = 2
        c.KubeSpawner.mem_limit = '4G'
        c.KubeSpawner.privileged = False
    """))
    result = parse_config(cfg)
    settings = result.get_class_settings("KubeSpawner")
    assert settings == {"cpu_limit": 2, "mem_limit": "4G", "privileged": False}


def test_last_value_wins(tmp_path: Path):
    cfg = tmp_path / "jupyterhub_config.py"
    cfg.write_text(textwrap.dedent("""\
        c.JupyterHub.ip = '127.0.0.1'
        c.JupyterHub.ip = '0.0.0.0'
    """))
    result = parse_config(cfg)
    assert result.get("JupyterHub", "ip") == "0.0.0.0"


def test_non_traitlet_assignments_ignored(tmp_path: Path):
    cfg = tmp_path / "jupyterhub_config.py"
    cfg.write_text(textwrap.dedent("""\
        x = 42
        my_var = 'hello'
        c.JupyterHub.ip = '127.0.0.1'
    """))
    result = parse_config(cfg)
    assert len(result.assignments) == 1

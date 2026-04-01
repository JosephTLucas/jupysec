"""Safe AST-based parser for jupyterhub_config.py.

Extracts ``c.ClassName.trait = value`` assignments without executing the file.
Handles the vast majority of real-world JupyterHub configs where traits are
set to literal values (strings, numbers, booleans, lists, dicts).
"""

from __future__ import annotations

import ast
from dataclasses import dataclass, field
from pathlib import Path


@dataclass
class ConfigAssignment:
    """A single ``c.ClassName.trait = value`` extracted from config."""

    classname: str
    trait: str
    value: object
    raw_source: str
    lineno: int
    resolved: bool = True


@dataclass
class ParsedConfig:
    """Result of parsing a jupyterhub_config.py file."""

    path: str
    assignments: list[ConfigAssignment] = field(default_factory=list)
    unresolved: list[ConfigAssignment] = field(default_factory=list)
    errors: list[str] = field(default_factory=list)

    def get(self, classname: str, trait: str, default: object = None) -> object:
        """Look up the last assigned value for c.ClassName.trait."""
        for a in reversed(self.assignments):
            if a.classname == classname and a.trait == trait and a.resolved:
                return a.value
        return default

    def has(self, classname: str, trait: str) -> bool:
        return any(
            a.classname == classname and a.trait == trait
            for a in self.assignments
        )

    def get_class_settings(self, classname: str) -> dict[str, object]:
        """Return all resolved trait values for a given class."""
        result: dict[str, object] = {}
        for a in self.assignments:
            if a.classname == classname and a.resolved:
                result[a.trait] = a.value
        return result


def _try_literal_eval(node: ast.expr) -> tuple[object, bool]:
    """Attempt to evaluate an AST node as a literal. Returns (value, success)."""
    try:
        value = ast.literal_eval(node)
        return value, True
    except (ValueError, TypeError):
        return None, False


def _is_traitlet_target(node: ast.Assign) -> tuple[str, str] | None:
    """Check if an Assign is ``c.ClassName.trait = ...`` and return (class, trait)."""
    if len(node.targets) != 1:
        return None

    target = node.targets[0]
    if not isinstance(target, ast.Attribute):
        return None

    # c.ClassName.trait
    mid = target.value
    if not isinstance(mid, ast.Attribute):
        return None

    root = mid.value
    if not (isinstance(root, ast.Name) and root.id == "c"):
        return None

    return mid.attr, target.attr


def parse_config(path: str | Path) -> ParsedConfig:
    """Parse a jupyterhub_config.py file via AST and extract trait assignments."""
    path = Path(path)
    result = ParsedConfig(path=str(path))

    try:
        source = path.read_text(encoding="utf-8")
    except OSError as exc:
        result.errors.append(f"Cannot read file: {exc}")
        return result

    try:
        tree = ast.parse(source, filename=str(path))
    except SyntaxError as exc:
        result.errors.append(f"Syntax error: {exc}")
        return result

    lines = source.splitlines()

    for node in ast.walk(tree):
        if not isinstance(node, ast.Assign):
            continue

        info = _is_traitlet_target(node)
        if info is None:
            continue

        classname, trait = info
        lineno = node.lineno
        raw = lines[lineno - 1].strip() if lineno <= len(lines) else ""

        value, resolved = _try_literal_eval(node.value)
        assignment = ConfigAssignment(
            classname=classname,
            trait=trait,
            value=value,
            raw_source=raw,
            lineno=lineno,
            resolved=resolved,
        )

        if resolved:
            result.assignments.append(assignment)
        else:
            result.unresolved.append(assignment)

    return result

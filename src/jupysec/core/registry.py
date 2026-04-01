"""Auto-discovery and registration of check modules."""

from __future__ import annotations

import importlib
import pkgutil
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from jupysec.checks.base import BaseCheck


def _is_concrete_check(obj: object) -> bool:
    from jupysec.checks.base import BaseCheck

    return (
        isinstance(obj, type)
        and issubclass(obj, BaseCheck)
        and obj is not BaseCheck
        and not getattr(obj, "__abstractmethods__", False)
        and hasattr(obj, "id")
    )


def discover_checks() -> list[BaseCheck]:
    """Walk the jupysec.checks package and return instantiated checks."""
    import jupysec.checks as checks_pkg

    instances: list[BaseCheck] = []
    seen_ids: set[str] = set()

    for importer, modname, ispkg in pkgutil.walk_packages(
        checks_pkg.__path__, prefix=checks_pkg.__name__ + "."
    ):
        try:
            module = importlib.import_module(modname)
        except Exception:
            continue

        for attr_name in dir(module):
            obj = getattr(module, attr_name)
            if _is_concrete_check(obj) and obj.id not in seen_ids:
                seen_ids.add(obj.id)
                instances.append(obj())

    instances.sort(key=lambda c: c.id)
    return instances

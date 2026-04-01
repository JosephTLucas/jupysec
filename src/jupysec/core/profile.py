"""Scan profiles define which subsets of checks to run."""

from __future__ import annotations

from enum import Enum

from pydantic import BaseModel


class Mode(str, Enum):
    EXTERNAL = "external"
    INTERNAL = "internal"
    FULL = "full"


class ProfileName(str, Enum):
    QUICK = "quick"
    DEFAULT = "default"
    THOROUGH = "thorough"


class ScanProfile(BaseModel):
    """Configuration for a scan run."""

    name: ProfileName = ProfileName.DEFAULT
    mode: Mode = Mode.EXTERNAL
    concurrency: int = 10
    include_checks: list[str] | None = None
    exclude_checks: list[str] | None = None

    def should_run_check(self, check_id: str, check_mode: Mode | str) -> bool:
        """Determine if a check should run given this profile."""
        check_mode_str = check_mode.value if isinstance(check_mode, Mode) else check_mode

        if self.mode == Mode.EXTERNAL and check_mode_str == Mode.INTERNAL.value:
            return False
        if self.mode == Mode.INTERNAL and check_mode_str == Mode.EXTERNAL.value:
            return False

        if self.include_checks is not None:
            if not any(check_id.startswith(pat) for pat in self.include_checks):
                return False

        if self.exclude_checks is not None:
            if any(check_id.startswith(pat) for pat in self.exclude_checks):
                return False

        return True

"""Base class for all security checks."""

from __future__ import annotations

from abc import ABC, abstractmethod

from jupysec.core.finding import Category, Finding, Severity
from jupysec.core.target import Target


class BaseCheck(ABC):
    """Abstract base for a security check.

    Subclasses must define class-level metadata and implement ``run``.
    The registry auto-discovers all concrete subclasses found under the
    ``jupysec.checks`` package.
    """

    id: str
    title: str
    severity: Severity
    category: Category
    mode: str  # "external", "internal", or "both"
    cwe: str | None = None
    references: list[str] = []

    def prerequisites_met(self, target: Target) -> bool:
        """Return True if the target provides enough info for this check."""
        if self.mode == "external":
            return target.has_external
        if self.mode == "internal":
            return target.has_internal
        return target.has_external or target.has_internal

    @abstractmethod
    async def run(self, target: Target) -> list[Finding]:
        """Execute the check and return findings (empty list = pass)."""
        ...

    def __repr__(self) -> str:
        return f"<Check {self.id}>"

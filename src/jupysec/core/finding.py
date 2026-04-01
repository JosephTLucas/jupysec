"""Structured finding model for security assessment results."""

from __future__ import annotations

import uuid as _uuid
from datetime import datetime, timezone
from enum import Enum

from pydantic import BaseModel, Field


class Severity(str, Enum):
    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    INFO = "info"


SEVERITY_ORDER = {
    Severity.CRITICAL: 0,
    Severity.HIGH: 1,
    Severity.MEDIUM: 2,
    Severity.LOW: 3,
    Severity.INFO: 4,
}


class Category(str, Enum):
    AUTH = "auth"
    NETWORK = "network"
    API = "api"
    WEBSOCKET = "websocket"
    ISOLATION = "isolation"
    CONFIG = "config"
    KUBERNETES = "kubernetes"
    SUPPLY_CHAIN = "supply_chain"


class Finding(BaseModel):
    """A single security finding produced by a check."""

    id: str = Field(default_factory=lambda: str(_uuid.uuid4()))
    check_id: str
    severity: Severity
    title: str
    description: str
    evidence: str = ""
    remediation: str = ""
    cwe: str | None = None
    references: list[str] = Field(default_factory=list)
    target_component: str = ""
    benchmark_id: str | None = None
    timestamp: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))

    def sort_key(self) -> tuple[int, str]:
        return (SEVERITY_ORDER.get(self.severity, 99), self.check_id)


class ScanResult(BaseModel):
    """Aggregated results from a full scan."""

    target_url: str | None = None
    config_path: str | None = None
    mode: str = "external"
    started_at: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))
    completed_at: datetime | None = None
    findings: list[Finding] = Field(default_factory=list)
    checks_run: int = 0
    checks_passed: int = 0
    checks_failed: int = 0
    checks_errored: int = 0

    @property
    def summary(self) -> dict[str, int]:
        counts: dict[str, int] = {}
        for f in self.findings:
            counts[f.severity.value] = counts.get(f.severity.value, 0) + 1
        return counts

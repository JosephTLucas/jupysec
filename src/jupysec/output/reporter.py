"""Report generation in multiple formats."""

from __future__ import annotations

import json
from pathlib import Path

from jupysec.core.finding import ScanResult


def to_json(result: ScanResult, *, indent: int = 2) -> str:
    return result.model_dump_json(indent=indent)


def write_json(result: ScanResult, path: Path) -> None:
    path.write_text(to_json(result), encoding="utf-8")


def to_sarif(result: ScanResult) -> str:
    """Produce a minimal SARIF 2.1.0 document from scan results."""
    rules = {}
    sarif_results = []

    for f in result.findings:
        if f.check_id not in rules:
            rules[f.check_id] = {
                "id": f.check_id,
                "shortDescription": {"text": f.title},
                "helpUri": f.references[0] if f.references else "",
                "properties": {"severity": f.severity.value},
            }

        sarif_results.append({
            "ruleId": f.check_id,
            "level": _sarif_level(f.severity.value),
            "message": {"text": f.description},
            "properties": {
                "evidence": f.evidence,
                "remediation": f.remediation,
                "component": f.target_component,
            },
        })

    sarif = {
        "$schema": "https://raw.githubusercontent.com/oasis-tcs/sarif-spec/main/sarif-2.1/schema/sarif-schema-2.1.0.json",
        "version": "2.1.0",
        "runs": [
            {
                "tool": {
                    "driver": {
                        "name": "jupysec",
                        "version": result.mode,
                        "informationUri": "https://github.com/jupysec/jupysec",
                        "rules": list(rules.values()),
                    }
                },
                "results": sarif_results,
            }
        ],
    }
    return json.dumps(sarif, indent=2)


def write_sarif(result: ScanResult, path: Path) -> None:
    path.write_text(to_sarif(result), encoding="utf-8")


_SEVERITY_MAP = {
    "critical": "error",
    "high": "error",
    "medium": "warning",
    "low": "note",
    "info": "note",
}


def _sarif_level(severity: str) -> str:
    return _SEVERITY_MAP.get(severity, "none")

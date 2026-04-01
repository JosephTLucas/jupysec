# Contributing to jupysec

## Adding a new check

Each check is a Python class inheriting from `BaseCheck`. The registry discovers them automatically -- no registration needed.

1. Create a file in the appropriate `src/jupysec/checks/<category>/` directory.
2. Define a class with the required metadata and implement `async def run`.
3. Run `jupysec checks` to verify it appears.

```python
from jupysec.checks.base import BaseCheck
from jupysec.core.finding import Category, Finding, Severity
from jupysec.core.target import Target


class MyCheck(BaseCheck):
    id = "category/my-check"        # Unique ID
    title = "Short description"      # Shown in tables
    severity = Severity.HIGH         # CRITICAL, HIGH, MEDIUM, LOW, INFO
    category = Category.AUTH         # AUTH, NETWORK, API, WEBSOCKET, ISOLATION, CONFIG, KUBERNETES, SUPPLY_CHAIN
    mode = "external"                # "external", "internal", or "both"
    cwe = "CWE-xxx"                  # Optional
    references = ["https://..."]     # Optional

    async def run(self, target: Target) -> list[Finding]:
        # Return [] for pass, [Finding(...)] for fail
        ...
```

### Attack checks vs. compliance checks

Prefer checks that model real attacker behavior (`attack/*` prefix) over passive configuration audits. A good attack check:

- Actually **tries** the attack (makes the request, executes the code, connects the socket)
- Reports what **succeeded**, not what *might* be wrong
- Includes concrete **evidence** of what was observed
- Provides specific **remediation** steps

## Setup

```bash
uv venv && uv pip install -e ".[dev]"
pytest
```

## Running tests

```bash
pytest                     # all tests
pytest -v                  # verbose
pytest tests/test_foo.py   # single file
pytest -k "test_name"      # by name
```

## Code style

The project uses `ruff` for linting. Run `ruff check src/ tests/` before committing.

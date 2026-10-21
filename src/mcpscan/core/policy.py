""".mcpscan.yaml: per-project settings and finding suppressions.

```yaml
fail_on: high          # exit 1 at or above this severity (the --fail-on flag wins)
strict: true           # exit 2 if any server couldn't be connected to (--strict wins)
suppress:
  - rule_id: MCP-CF-001          # exact id or glob ("MCP-TP-*")
    server: internal-db          # server name, glob allowed
    tool: query                  # optional
    finding_id: 3f2a9c...        # optional: one specific finding
    reason: Secret is injected by vault at runtime   # required
    expires: 2027-01-01          # optional: stops applying after this date
```

Each suppression needs a reason and at least one selector. A suppressed finding still appears in
JSON and SARIF output, marked suppressed with its reason, so suppressions can be audited.
"""

from __future__ import annotations

from collections.abc import Sequence
from datetime import date
from fnmatch import fnmatchcase
from pathlib import Path
from typing import Any, Self

import yaml
from pydantic import Field, model_validator

from mcpscan.core.models import Finding, ScanResult, Severity, StrictModel, SuppressedFinding

POLICY_FILE = ".mcpscan.yaml"


class PolicyError(Exception):
    pass


class Suppression(StrictModel):
    reason: str = Field(min_length=1)
    rule_id: str | None = None
    server: str | None = None
    tool: str | None = None
    finding_id: str | None = None
    expires: date | None = None

    @model_validator(mode="after")
    def _has_selector(self) -> Self:
        if not (self.rule_id or self.server or self.tool or self.finding_id):
            raise ValueError("a suppression needs rule_id, server, tool or finding_id")
        return self

    def matches(self, finding: Finding, server_name: str) -> bool:
        checks = (
            (self.rule_id, finding.rule_id),
            (self.server, server_name),
            (self.tool, finding.location.tool or ""),
        )
        if any(
            pattern is not None and not fnmatchcase(value, pattern) for pattern, value in checks
        ):
            return False
        return self.finding_id is None or self.finding_id == finding.id

    def describe(self) -> str:
        selectors = {"rule_id": self.rule_id, "server": self.server, "tool": self.tool,
                     "finding_id": self.finding_id}  # fmt: skip
        return ", ".join(f"{k}={v}" for k, v in selectors.items() if v)


class Policy(StrictModel):
    fail_on: Severity | None = None
    strict: bool = False
    suppress: list[Suppression] = Field(default_factory=list[Suppression])

    @classmethod
    def load(cls, path: Path) -> Policy:
        try:
            data: Any = yaml.safe_load(path.read_text(encoding="utf-8"))
        except (OSError, yaml.YAMLError) as exc:
            raise PolicyError(f"could not read {path}: {exc}") from exc
        try:
            return cls.model_validate(data or {})
        except ValueError as exc:
            raise PolicyError(f"{path} is not a valid policy:\n{exc}") from exc

    def apply(self, result: ScanResult, *, today: date | None = None) -> ScanResult:
        """Move matching findings to `suppressed`; warn about expired suppressions."""
        today = today or date.today()
        names = {s.id: s.name for s in result.servers}
        active: Sequence[Suppression] = [
            s for s in self.suppress if not s.expires or s.expires >= today
        ]
        warnings = [
            f"suppression ({s.describe()}) expired on {s.expires}; it no longer applies"
            for s in self.suppress
            if s.expires and s.expires < today
        ]
        kept: list[Finding] = []
        suppressed = list(result.suppressed)
        for finding in result.findings:
            server = names.get(finding.location.server_id, finding.location.server_id)
            match = next((s for s in active if s.matches(finding, server)), None)
            if match is None:
                kept.append(finding)
            else:
                suppressed.append(SuppressedFinding(finding=finding, reason=match.reason))
        return result.model_copy(
            update={
                "findings": kept,
                "suppressed": suppressed,
                "warnings": [*result.warnings, *warnings],
            }
        )

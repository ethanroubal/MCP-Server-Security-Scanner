"""The rule plugin interface. Every L1 deterministic check is a `Rule` subclass."""

from __future__ import annotations

import re
from abc import ABC, abstractmethod
from collections.abc import Sequence
from dataclasses import dataclass
from typing import ClassVar, Literal

from mcpiranha.core.hashing import hash_json
from mcpiranha.core.lockfile import Lockfile
from mcpiranha.core.models import (
    Category,
    Confidence,
    Detector,
    Evidence,
    Finding,
    Location,
    ServerSnapshot,
    Severity,
)

Target = Literal["tool", "prompt", "resource", "config", "source", "package"]

RULE_ID_PATTERN = re.compile(r"^MCP-(TP|XS|RP|CF|SRC|SC|TF|DY)-\d{3}$")


@dataclass(frozen=True, slots=True)
class RuleContext:
    snapshot: ServerSnapshot  # the server being checked
    # The servers one agent sees together (same client), for cross-server rules.
    inventory: Sequence[ServerSnapshot]
    lock: Lockfile | None = None  # pinned state to compare against (MCP-RP-001)


class Rule(ABC):
    """Subclass, fill in the class attributes, implement `run`, and decorate with `@register`."""

    id: ClassVar[str]  # "MCP-TP-001", see docs/RULES.md
    title: ClassVar[str]
    category: ClassVar[Category]
    default_severity: ClassVar[Severity]
    applies_to: ClassVar[frozenset[Target]]
    remediation: ClassVar[str]
    references: ClassVar[tuple[str, ...]] = ()

    @abstractmethod
    def run(self, ctx: RuleContext) -> list[Finding]: ...

    def finding(
        self,
        *,
        location: Location,
        evidence: list[Evidence],
        rationale: str,
        severity: Severity | None = None,
        confidence: Confidence = Confidence.HIGH,
        remediation: str | None = None,
    ) -> Finding:
        """Build a `Finding` with this rule's defaults. The id is a hash of rule, location and
        evidence, so it stays the same across runs and can be used in suppressions."""
        fid = hash_json(
            {
                "rule": self.id,
                "location": location.model_dump(mode="json"),
                "evidence": [e.text for e in evidence],
            }
        )[:16]
        return Finding(
            id=fid,
            rule_id=self.id,
            title=self.title,
            category=self.category,
            severity=severity or self.default_severity,
            confidence=confidence,
            detector=Detector.RULE,
            location=location,
            evidence=evidence,
            rationale=rationale,
            remediation=remediation or self.remediation,
            references=list(self.references),
        )

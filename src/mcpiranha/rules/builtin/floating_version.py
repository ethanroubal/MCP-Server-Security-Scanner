"""MCP-RP-003: the launched package or image isn't pinned to an immutable version.

`npx -y pkg` and `uvx pkg` fetch the newest release at every launch. Whoever controls the package
(its maintainer, or someone who stole their token) can change what runs on your machine with a
publish, no config change needed. Docker tags are mutable too; only a digest is fixed.
"""

from __future__ import annotations

from mcpiranha.core.launch import argv_pointer, command_line, package_ref
from mcpiranha.core.models import Category, Confidence, Evidence, Finding, Location, Severity
from mcpiranha.rules.base import Rule, RuleContext
from mcpiranha.rules.registry import register

_PIN_HINT = {
    "npm": "an exact version, e.g. {name}@1.2.3",
    "pypi": "an exact version, e.g. {name}==1.2.3",
    "docker": "a digest, e.g. {name}@sha256:...",
}


@register
class FloatingVersion(Rule):
    id = "MCP-RP-003"
    title = "Floating (unpinned) package version"
    category = Category.RUG_PULL
    default_severity = Severity.MEDIUM
    applies_to = frozenset({"config", "package"})
    remediation = (
        "Pin the exact version you reviewed, and update deliberately. Pair this with "
        "`mcpiranha lock` so changes to the tools themselves are caught too."
    )

    def run(self, ctx: RuleContext) -> list[Finding]:
        launch = ctx.snapshot.launch
        ref = package_ref(launch)
        if launch is None or ref is None or ref.pinned:
            return []
        if ref.spec is None or ref.spec == "latest":
            state, severity = "has no version, so the newest release runs", Severity.MEDIUM
        elif ref.registry == "docker":
            state, severity = f"uses tag {ref.spec!r}, which can be moved", Severity.LOW
        else:
            state, severity = (
                f"uses range {ref.spec!r}, which accepts new releases",
                Severity.MEDIUM,
            )
        return [
            self.finding(
                location=Location(
                    server_id=ctx.snapshot.id,
                    json_pointer=argv_pointer(launch, ref.argv_index),
                    file=ctx.snapshot.origin.config_path,
                ),
                evidence=[Evidence(text=command_line(launch)[ref.argv_index])],
                rationale=f"{ref.runner} {ref.display} {state}. Pin it to "
                + _PIN_HINT[ref.registry].format(name=ref.name)
                + ".",
                severity=severity,
                confidence=Confidence.HIGH,
            )
        ]

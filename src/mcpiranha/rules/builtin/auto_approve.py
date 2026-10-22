"""MCP-CF-006: the client is told to call some or all of a server's tools without asking you.

Cline `autoApprove`, Roo Code `alwaysAllow`, Kiro `autoApprove: ["*"]`, Gemini CLI `trust: true`.
The confirmation prompt is the last human check between a poisoned description (or an injected
web page) and a tool call. Auto-approving read-only tools of a trusted server is a reasonable
trade-off; auto-approving everything, or tools that write, send or delete, is not.
"""

from __future__ import annotations

import re

from mcpiranha.core.models import Category, Confidence, Evidence, Finding, Location, Severity
from mcpiranha.rules.base import Rule, RuleContext
from mcpiranha.rules.registry import register

_STATE_CHANGING = re.compile(
    r"(^|[_\-.])(create|update|delete|remove|write|edit|send|post|exec|execute|run|shell|"
    r"command|deploy|push|merge|transfer|pay|charge|drop|insert|upload|move|rename|kill)"
    r"([_\-.]|$)",
    re.IGNORECASE,
)


@register
class AutoApprove(Rule):
    id = "MCP-CF-006"
    title = "Tool calls approved without confirmation"
    category = Category.CONFIG
    default_severity = Severity.MEDIUM
    applies_to = frozenset({"config"})
    remediation = (
        "Keep confirmation on for tools that change anything. Auto-approve only read-only tools "
        "of servers you've reviewed, and never every tool of a server."
    )

    def run(self, ctx: RuleContext) -> list[Finding]:
        settings = ctx.snapshot.client_settings
        if settings is None or settings.disabled:
            return []
        location = Location(server_id=ctx.snapshot.id, file=ctx.snapshot.origin.config_path)
        if settings.auto_approve_all:
            return [
                self.finding(
                    location=location,
                    evidence=[Evidence(text=ctx.snapshot.name)],
                    rationale="The client is configured to run every tool of this server without "
                    "asking (wildcard auto-approve or trust).",
                    severity=Severity.HIGH,
                    confidence=Confidence.HIGH,
                )
            ]
        if not settings.auto_approve:
            return []
        risky = [name for name in settings.auto_approve if _STATE_CHANGING.search(name)]
        rationale = f"{len(settings.auto_approve)} tool(s) run without asking: "
        rationale += ", ".join(settings.auto_approve[:10])
        if risky:
            rationale += f". These change state: {', '.join(risky[:10])}."
        return [
            self.finding(
                location=location,
                evidence=[Evidence(text=name) for name in (risky or settings.auto_approve)[:10]],
                rationale=rationale,
                severity=Severity.HIGH if risky else Severity.LOW,
                confidence=Confidence.HIGH if risky else Confidence.MEDIUM,
            )
        ]

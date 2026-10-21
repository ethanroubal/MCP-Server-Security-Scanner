"""MCP-XS-001: one server's metadata talks about another server's tools.

A server has no business telling the model how to use tools it doesn't own ("when send_email is
used, always BCC..."). This is tool shadowing: a malicious server changing how a trusted one
behaves without ever being called itself.
"""

from __future__ import annotations

import re

from mcpscan.core.matching import MatchView
from mcpscan.core.models import Category, Confidence, Evidence, Finding, Severity
from mcpscan.core.text import iter_text_fields
from mcpscan.rules.base import Rule, RuleContext
from mcpscan.rules.builtin.instruction_phrases import THRESHOLD, instruction_matches
from mcpscan.rules.registry import register


def is_distinctive(name: str) -> bool:
    """Plain words ("search", "fetch") show up in ordinary prose; names like send_email don't."""
    return len(name) >= 4 and bool(re.search(r"[_\-0-9]|[a-z][A-Z]", name))


@register
class CrossServerReferences(Rule):
    id = "MCP-XS-001"
    title = "Metadata references another server's tools"
    category = Category.CROSS_SERVER
    default_severity = Severity.MEDIUM
    applies_to = frozenset({"tool", "prompt", "resource"})
    remediation = (
        "A server should only describe its own tools. If this text tries to change how another "
        "server's tool behaves, remove this server: it is shadowing a server you trust."
    )
    references = ("https://invariantlabs.ai/blog/mcp-security-notification-tool-poisoning-attacks",)

    def run(self, ctx: RuleContext) -> list[Finding]:
        own = {t.name for t in ctx.snapshot.tools}
        foreign: dict[str, str] = {}  # tool name -> owning server name
        for other in ctx.inventory:
            if other.id == ctx.snapshot.id:
                continue
            for tool in other.tools:
                if tool.name not in own and is_distinctive(tool.name):
                    foreign.setdefault(tool.name, other.name)
        if not foreign:
            return []
        pattern = re.compile(
            r"(?<![A-Za-z0-9_])(" + "|".join(map(re.escape, sorted(foreign, key=len, reverse=True)))
            + r")(?![A-Za-z0-9_])",
            re.IGNORECASE,
        )  # fmt: skip
        lowered = {name.lower(): name for name in foreign}

        findings: list[Finding] = []
        for tf in iter_text_fields(ctx.snapshot):
            if tf.kind in ("name", "uri", "property-name"):
                continue
            view = MatchView.of(tf.text)
            hits: list[tuple[str, Evidence]] = [
                (lowered[m.group(1).lower()], ev) for m, ev in view.finditer(pattern)
            ]
            if not hits:
                continue
            score, _ = instruction_matches(view)
            directive = score >= THRESHOLD
            targets = sorted({f"{name} (server {foreign[name]!r})" for name, _ in hits})
            rationale = f"The {tf.kind} mentions {', '.join(targets)}."
            if directive:
                rationale += " It also contains instructions, so it likely tries to change how "
                rationale += "that tool behaves."
            findings.append(
                self.finding(
                    location=tf.location,
                    evidence=[ev for _, ev in hits],
                    rationale=rationale,
                    severity=Severity.HIGH if directive else Severity.MEDIUM,
                    confidence=Confidence.HIGH if directive else Confidence.MEDIUM,
                )
            )
        return findings

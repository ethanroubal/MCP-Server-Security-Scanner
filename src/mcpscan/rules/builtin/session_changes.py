"""MCP-RP-002: the server's tools changed while mcpscan was connected.

Clients show you tool descriptions when you approve a server, then keep using whatever the server
serves later. A server that changes its tools mid-session (or announces it with
`notifications/tools/list_changed`) can swap a reviewed description for a poisoned one after
approval. Some servers legitimately add tools dynamically; a change during a plain listing, with
no tool ever called, is still worth a look.
"""

from __future__ import annotations

from mcpscan.core.models import Category, Confidence, Evidence, Finding, Location, Severity
from mcpscan.rules.base import Rule, RuleContext
from mcpscan.rules.registry import register


@register
class SessionChanges(Rule):
    id = "MCP-RP-002"
    title = "Tools changed during a session"
    category = Category.RUG_PULL
    default_severity = Severity.HIGH
    applies_to = frozenset({"tool"})
    remediation = (
        "Find out why the tool list changes without any tool being called. Review the tools as "
        "they are after the change, and pin them with `mcpscan lock --connect`."
    )

    def run(self, ctx: RuleContext) -> list[Finding]:
        findings: list[Finding] = []
        for obs in ctx.snapshot.observations:
            if obs.kind != "tools_changed":
                continue
            # A changed definition is the attack itself; tools appearing or disappearing is
            # suspicious; a list_changed notification alone is weak (some servers send one at
            # startup, as they register tools).
            if "changed:" in obs.detail:
                severity, confidence = Severity.HIGH, Confidence.HIGH
            elif "between two calls" in obs.detail:
                severity, confidence = Severity.MEDIUM, Confidence.MEDIUM
            else:
                severity, confidence = Severity.LOW, Confidence.LOW
            findings.append(
                self.finding(
                    location=Location(server_id=ctx.snapshot.id, json_pointer="/tools"),
                    evidence=[Evidence(text=obs.detail)],
                    rationale=f"While only listing, the server's tools changed: {obs.detail}.",
                    severity=severity,
                    confidence=confidence,
                )
            )
        return findings

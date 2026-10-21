"""MCP-CF-003: a remote server lists its tools to anyone, with no credentials.

Fine for a public documentation server. Not fine for one whose tools read your data or change
things: anyone who finds the URL can use them, and nothing ties a call to you.
"""

from __future__ import annotations

import re

from mcpscan.core.models import Category, Confidence, Evidence, Finding, Location, Severity
from mcpscan.rules.base import Rule, RuleContext
from mcpscan.rules.registry import register

# Tool names that suggest the server does more than serve public information.
_STATEFUL = re.compile(
    r"(^|[_\-.])(create|update|delete|remove|write|send|post|exec|execute|run|deploy|transfer|"
    r"pay|charge|refund|set|put|insert|drop|modify|edit|upload|admin)([_\-.]|$)",
    re.IGNORECASE,
)


@register
class RemoteNoAuth(Rule):
    id = "MCP-CF-003"
    title = "Remote server without authentication"
    category = Category.CONFIG
    default_severity = Severity.LOW
    applies_to = frozenset({"config"})
    remediation = (
        "If this server can read private data or change anything, it should require "
        "authentication (MCP specifies OAuth). If it only serves public information, this is fine."
    )

    def run(self, ctx: RuleContext) -> list[Finding]:
        observed = [o for o in ctx.snapshot.observations if o.kind == "auth_not_required"]
        if not observed:
            return []
        stateful = sorted(t.name for t in ctx.snapshot.tools if _STATEFUL.search(t.name))
        rationale = f"The server {observed[0].detail}."
        if stateful:
            rationale += f" Some of them change state: {', '.join(stateful[:8])}."
        url = ctx.snapshot.launch.url if ctx.snapshot.launch else None
        return [
            self.finding(
                location=Location(server_id=ctx.snapshot.id, json_pointer="/launch/url"),
                evidence=[Evidence(text=name) for name in stateful[:8]]
                or [Evidence(text=(url or ctx.snapshot.name).split("?", 1)[0])],
                rationale=rationale,
                severity=Severity.MEDIUM if stateful else Severity.LOW,
                confidence=Confidence.MEDIUM,
            )
        ]

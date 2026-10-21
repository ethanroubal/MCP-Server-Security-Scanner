"""MCP-XS-002: two servers expose tools with the same, or deceptively similar, names.

With identical names the client or model may call the wrong server's tool. A look-alike name (a
Cyrillic letter in `read_file`) is worse: it is built to be mistaken for the real tool.
"""

from __future__ import annotations

from mcpscan.core.confusables import skeleton
from mcpscan.core.models import Category, Confidence, Evidence, Finding, Location, Severity
from mcpscan.core.text import reveal
from mcpscan.rules.base import Rule, RuleContext
from mcpscan.rules.registry import register


@register
class ToolNameCollision(Rule):
    id = "MCP-XS-002"
    title = "Tool name collides with another server's tool"
    category = Category.CROSS_SERVER
    default_severity = Severity.MEDIUM
    applies_to = frozenset({"tool"})
    remediation = (
        "Don't run both servers in the same client unless you can tell their tools apart. A "
        "look-alike name is a deliberate impersonation: remove that server."
    )

    def run(self, ctx: RuleContext) -> list[Finding]:
        position = {s.id: i for i, s in enumerate(ctx.inventory)}
        me = position.get(ctx.snapshot.id, len(ctx.inventory))
        findings: list[Finding] = []
        for i, tool in enumerate(ctx.snapshot.tools):
            key = skeleton(tool.name)
            for other in ctx.inventory:
                if other.id == ctx.snapshot.id:
                    continue
                for theirs in other.tools:
                    if skeleton(theirs.name) != key:
                        continue
                    location = Location(
                        server_id=ctx.snapshot.id, tool=tool.name, json_pointer=f"/tools/{i}/name"
                    )
                    if theirs.name == tool.name:
                        if position[other.id] > me:
                            continue  # report an exact duplicate once, on the later server
                        findings.append(
                            self.finding(
                                location=location,
                                evidence=[Evidence(text=tool.name, start=0, end=len(tool.name))],
                                rationale=f"Server {other.name!r} also has a tool named "
                                f"{reveal(tool.name)!r}.",
                                severity=Severity.MEDIUM,
                                confidence=Confidence.HIGH,
                            )
                        )
                    elif not tool.name.isascii():
                        findings.append(
                            self.finding(
                                location=location,
                                evidence=[Evidence(text=tool.name, start=0, end=len(tool.name))],
                                rationale=f"{reveal(_mark_non_ascii(tool.name))!r} looks like "
                                f"{theirs.name!r} from server {other.name!r} but uses different "
                                "characters.",
                                severity=Severity.HIGH,
                                confidence=Confidence.HIGH,
                            )
                        )
        return findings


def _mark_non_ascii(name: str) -> str:
    return "".join(c if c.isascii() else f"<U+{ord(c):04X}>" for c in name)

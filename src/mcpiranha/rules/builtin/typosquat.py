"""MCP-XS-003: the launched package's name is a near-miss of a well-known MCP server.

`@modelcontextprotocol/server-filesytem` (missing "s") installs whatever its publisher wants.
Package runners like `npx -y` fetch and run it with no prompt.
"""

from __future__ import annotations

import re

from mcpiranha.core.confusables import edit_distance, skeleton
from mcpiranha.core.launch import argv_pointer, package_ref
from mcpiranha.core.models import Category, Confidence, Evidence, Finding, Location, Severity
from mcpiranha.rules.base import Rule, RuleContext
from mcpiranha.rules.known_packages import KNOWN_NPM, KNOWN_PYPI
from mcpiranha.rules.registry import register

PYPI_FOLD = str.maketrans({"_": "-", ".": "-"})


# Words every MCP package name shares; comparing them makes different products look alike
_FILLER = frozenset({"mcp", "server", "servers", "mcpserver", "model", "context", "protocol",
                     "modelcontextprotocol", "io", "js", "ts", "py", "the"})  # fmt: skip
SAME_CORE = -1  # same distinctive name, different publisher or packaging


def split(name: str) -> tuple[str | None, str]:
    """(scope, distinctive core of the unscoped name): `@sentry/mcp-server` -> ("sentry", "")."""
    scope, _, base = name.lower()[1:].partition("/") if name.startswith("@") else ("", "", name)
    words = [w for w in re.split(r"[._-]+", base.lower()) if w and w not in _FILLER]
    return (scope or None), "-".join(words)


def _within(a: str, b: str, *, long: int = 10, short: int = 6) -> int | None:
    """Edit distance if a and b are near-misses (2 edits on long names, 1 on medium, none on
    short ones), else None."""
    allowed = 2 if len(b) >= long else 1 if len(b) >= short else 0
    if not allowed or a == b:
        return None
    d = edit_distance(a, b, limit=3)
    return d if d <= allowed else None


def closest(name: str, known: frozenset[str]) -> tuple[str, int] | None:
    """The known name this one imitates, and how: 0 = look-alike characters, SAME_CORE =
    impersonates a publisher or reuses a popular name under another scope, n > 0 = n edits.

    Matches the shapes npm typosquats take rather than general similarity, because calibration
    against the whole MCP registry (calibration/update_known_packages.py --check) showed that
    different organizations routinely publish similar short names (@x/agent, @y/agent):
    - unscoped near-miss of an unscoped name (kobsidian-mcp ~ obsidian-mcp-server),
    - the same package under a near-miss scope (@modelcontextprotoco/server-filesystem),
    - an unscoped package named after a known publisher (sentry-mcp-server ~ @sentry/...),
    - a popular unscoped name republished under some scope (@x/rea-agents ~ rea-agents).
    Edits are counted on the distinctive part of the name (words like "mcp" and "server"
    removed), which must be long enough to mean something.
    """
    if name in known:
        return None
    key = skeleton(name)
    scope, mine = split(name)
    best: tuple[str, int] | None = None

    def offer(candidate: str, how: int) -> None:
        nonlocal best
        if best is None or (best[1] != SAME_CORE and (how == SAME_CORE or how < best[1])):
            best = (candidate, how)

    for candidate in known:
        if skeleton(candidate) == key:
            return candidate, 0
        their_scope, theirs = split(candidate)
        if scope and their_scope:
            if (
                scope != their_scope
                and mine == theirs
                and (d := _within(scope, their_scope)) is not None
            ):
                offer(candidate, d)  # same package, near-miss scope
        elif scope is None and their_scope:
            if len(their_scope) >= 4 and mine == their_scope:
                offer(candidate, SAME_CORE)  # named after the publisher
        elif scope and their_scope is None:
            if len(theirs) >= 6 and mine == theirs:
                offer(candidate, SAME_CORE)  # popular unscoped name under another scope
        elif (d := _within(mine, theirs)) is not None:
            offer(candidate, d)  # both unscoped: near-miss
    return best


@register
class Typosquat(Rule):
    id = "MCP-XS-003"
    title = "Package name imitates a well-known MCP server"
    category = Category.CROSS_SERVER
    default_severity = Severity.HIGH
    applies_to = frozenset({"config", "package"})
    remediation = (
        "Check the package name letter by letter against the official one. If it's a near-miss, "
        "remove it from your config and assume anything it could access is compromised."
    )

    def run(self, ctx: RuleContext) -> list[Finding]:
        ref = package_ref(ctx.snapshot.launch)
        if ref is None or ref.registry == "docker":
            return []
        if ref.registry == "npm":
            match = closest(ref.name, KNOWN_NPM)
        else:
            match = closest(ref.name.lower().translate(PYPI_FOLD), KNOWN_PYPI)
        if match is None:
            return []
        target, distance = match
        if distance == 0:
            how, severity = "uses look-alike characters to imitate", Severity.HIGH
        elif distance == SAME_CORE:
            # Often a fork; sometimes "starjacking". Either way not the package people mean.
            how, severity = "isn't, but reuses the name or publisher of,", Severity.MEDIUM
        else:
            how, severity = f"is {distance} edit(s) away from", Severity.HIGH
        assert ctx.snapshot.launch is not None  # package_ref returned a match
        pointer = argv_pointer(ctx.snapshot.launch, ref.argv_index)
        return [
            self.finding(
                location=Location(server_id=ctx.snapshot.id, json_pointer=pointer),
                evidence=[Evidence(text=ref.name)],
                rationale=f"{ref.registry} package {ref.name!r} {how} the well-known {target!r}."
                + (" It may be a fork: check who publishes it." if distance == SAME_CORE else ""),
                severity=severity,
                confidence=Confidence.HIGH if 0 <= distance <= 1 else Confidence.MEDIUM,
            )
        ]

"""MCP-XS-003: the launched package's name is a near-miss of a well-known MCP server.

`@modelcontextprotocol/server-filesytem` (missing "s") installs whatever its publisher wants.
Package runners like `npx -y` fetch and run it with no prompt.
"""

from __future__ import annotations

from mcpscan.core.confusables import edit_distance, skeleton
from mcpscan.core.launch import argv_pointer, package_ref
from mcpscan.core.models import Category, Confidence, Evidence, Finding, Location, Severity
from mcpscan.rules.base import Rule, RuleContext
from mcpscan.rules.known_packages import KNOWN_NPM, KNOWN_PYPI
from mcpscan.rules.registry import register

_PYPI_FOLD = str.maketrans({"_": "-", ".": "-"})


def _closest(name: str, known: frozenset[str]) -> tuple[str, int] | None:
    """The known name this one imitates, and the edit distance (0 = look-alike characters)."""
    if name in known:
        return None
    key = skeleton(name)
    best: tuple[str, int] | None = None
    for candidate in known:
        if skeleton(candidate) == key:
            return candidate, 0
        allowed = 1 if len(candidate) < 12 else 2
        if (
            len(candidate) >= 8
            and (d := edit_distance(name, candidate, limit=3)) <= allowed
            and (best is None or d < best[1])
        ):
            best = (candidate, d)
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
            match = _closest(ref.name, KNOWN_NPM)
        else:
            match = _closest(ref.name.lower().translate(_PYPI_FOLD), KNOWN_PYPI)
        if match is None:
            return []
        target, distance = match
        how = "uses look-alike characters" if distance == 0 else f"is {distance} edit(s) away"
        assert ctx.snapshot.launch is not None  # package_ref returned a match
        pointer = argv_pointer(ctx.snapshot.launch, ref.argv_index)
        return [
            self.finding(
                location=Location(server_id=ctx.snapshot.id, json_pointer=pointer),
                evidence=[Evidence(text=ref.name)],
                rationale=f"{ref.registry} package {ref.name!r} {how} from the well-known "
                f"{target!r}.",
                confidence=Confidence.HIGH if distance <= 1 else Confidence.MEDIUM,
            )
        ]

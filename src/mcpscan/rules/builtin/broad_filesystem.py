"""MCP-CF-005: a server granted the whole filesystem or the whole home directory.

Filesystem-style servers take their allowed roots as arguments. Rooting one at `/` or `~` puts
SSH keys, cloud credentials and every other client's config within reach of any prompt injection.
"""

from __future__ import annotations

import re

from mcpscan.core.launch import argv_pointer, command_line, package_ref
from mcpscan.core.models import Category, Evidence, Finding, Location, Severity
from mcpscan.rules.base import Rule, RuleContext
from mcpscan.rules.registry import register

_ROOT = re.compile(r"^(/|[A-Za-z]:\\?|[A-Za-z]:/|\\\\)$")
_HOME = re.compile(
    r"^(~|\$HOME|\$\{HOME\}|%USERPROFILE%|%HOMEPATH%|/Users/[^/]+|/home/[^/]+|/root|"
    r"[A-Za-z]:[\\/]Users[\\/][^\\/]+)[\\/]?$"
)


def is_root(path: str) -> bool:
    return bool(_ROOT.match(path.strip()))


def is_home(path: str) -> bool:
    return bool(_HOME.match(path.strip()))


@register
class BroadFilesystem(Rule):
    id = "MCP-CF-005"
    title = "Over-broad filesystem scope"
    category = Category.CONFIG
    default_severity = Severity.MEDIUM
    applies_to = frozenset({"config"})
    remediation = (
        "Give the server only the project directories it needs, e.g. ~/code/my-project, never / "
        "or your whole home directory."
    )

    def run(self, ctx: RuleContext) -> list[Finding]:
        launch = ctx.snapshot.launch
        if launch is None or launch.transport != "stdio" or not launch.command:
            return []
        argv = command_line(launch)
        ref = package_ref(launch)
        findings: list[Finding] = []
        for i, arg in enumerate(argv[1:], 1):
            if ref is not None and i == ref.argv_index:
                continue
            value = arg.split("=", 1)[1] if arg.startswith("--") and "=" in arg else arg
            if is_root(value):
                severity, what = Severity.HIGH, "the entire filesystem"
            elif is_home(value):
                severity, what = Severity.MEDIUM, "your entire home directory"
            else:
                continue
            findings.append(
                self.finding(
                    location=Location(
                        server_id=ctx.snapshot.id,
                        json_pointer=argv_pointer(launch, i),
                        file=ctx.snapshot.origin.config_path,
                    ),
                    evidence=[Evidence(text=arg)],
                    rationale=f"Argument {arg!r} gives the server access to {what}.",
                    severity=severity,
                )
            )
        return findings

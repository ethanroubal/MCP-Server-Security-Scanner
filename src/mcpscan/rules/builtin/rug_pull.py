"""MCP-RP-001: a server changed since it was pinned in mcp-lock.json.

You approved a server as it was. A rug pull changes it afterwards: a new release with a poisoned
description, or a config edit that swaps the package. Only runs when a lockfile is in use.
"""

from __future__ import annotations

import difflib
import json
from typing import Any

from mcpscan.core.hashing import hash_json
from mcpscan.core.launch import package_ref
from mcpscan.core.lockfile import launch_fingerprint
from mcpscan.core.models import Category, Confidence, Evidence, Finding, Location, Severity
from mcpscan.rules.base import Rule, RuleContext
from mcpscan.rules.registry import register

_MAX_DIFF_LINES = 24


def _diff(old: Any, new: Any) -> str:
    lines = difflib.unified_diff(
        json.dumps(old, indent=2, sort_keys=True, ensure_ascii=True).splitlines(),
        json.dumps(new, indent=2, sort_keys=True, ensure_ascii=True).splitlines(),
        fromfile="locked",
        tofile="current",
        n=1,
        lineterm="",
    )
    out = list(lines)[2:]  # drop the ---/+++ header
    if len(out) > _MAX_DIFF_LINES:
        out = [*out[:_MAX_DIFF_LINES], f"... {len(out) - _MAX_DIFF_LINES} more diff lines"]
    return "\n".join(out)


@register
class RugPull(Rule):
    id = "MCP-RP-001"
    title = "Server changed since it was locked"
    category = Category.RUG_PULL
    default_severity = Severity.HIGH
    applies_to = frozenset({"tool", "prompt", "resource", "config"})
    remediation = (
        "Review the change. If you expected it (you upgraded the server), re-run `mcpscan lock`. "
        "If you didn't, stop using the server until you know why it changed."
    )

    def run(self, ctx: RuleContext) -> list[Finding]:
        if ctx.lock is None:
            return []
        snapshot = ctx.snapshot
        sid = snapshot.id
        locked = ctx.lock.servers.get(sid)
        if locked is None:
            return []  # added servers are reported by `mcpscan verify`

        findings: list[Finding] = []
        if snapshot.launch is not None and locked.launch is not None:
            current = launch_fingerprint(snapshot.launch)
            if hash_json(current) != locked.launch_sha256:
                findings.append(
                    self.finding(
                        location=Location(
                            server_id=sid, json_pointer="/launch", file=snapshot.origin.config_path
                        ),
                        evidence=[Evidence(text=snapshot.name)],
                        rationale="The launch config changed:\n" + _diff(locked.launch, current),
                        severity=Severity.MEDIUM,
                    )
                )

        before, now = locked.package, snapshot.package
        if before and now and before.version and now.version and before.version != now.version:
            ref = package_ref(snapshot.launch)
            floating = ref is not None and not ref.pinned
            rationale = (
                f"{now.registry} package {now.name} now resolves to {now.version}; it was "
                f"{before.version} when locked."
            )
            if floating:
                rationale += " The config doesn't pin a version, so this changed without any edit."
            findings.append(
                self.finding(
                    location=Location(
                        server_id=sid, json_pointer="/launch", file=snapshot.origin.config_path
                    ),
                    evidence=[Evidence(text=now.version)],
                    rationale=rationale,
                    severity=Severity.HIGH if floating else Severity.MEDIUM,
                    confidence=Confidence.HIGH,
                )
            )

        if not snapshot.tools_listed or locked.tools is None:
            return findings  # nothing to compare tools against
        hashes = snapshot.hashes()
        current_tools = {t.name: (i, t) for i, t in enumerate(snapshot.tools)}
        for name, (i, tool) in current_tools.items():
            location = Location(server_id=sid, tool=name, json_pointer=f"/tools/{i}")
            before = locked.tools.get(name)
            if before is None:
                findings.append(
                    self.finding(
                        location=location,
                        evidence=[Evidence(text=name)],
                        rationale=f"New tool {name!r} appeared since the lock.",
                        severity=Severity.MEDIUM,
                    )
                )
            elif before.sha256 != hashes.tools[name]:
                after = tool.wire_dump()
                changed = sorted(k for k in {*before.definition, *after}
                                 if before.definition.get(k) != after.get(k))  # fmt: skip
                findings.append(
                    self.finding(
                        location=location,
                        evidence=[Evidence(text=tool.description or name)],
                        rationale=f"Tool {name!r} changed ({', '.join(changed)}):\n"
                        + _diff(before.definition, after),
                        severity=Severity.HIGH,
                        confidence=Confidence.HIGH,
                    )
                )
        for name in sorted(set(locked.tools) - set(current_tools)):
            findings.append(
                self.finding(
                    location=Location(server_id=sid, tool=name),
                    evidence=[Evidence(text=name)],
                    rationale=f"Tool {name!r} was removed since the lock.",
                    severity=Severity.LOW,
                )
            )
        return findings

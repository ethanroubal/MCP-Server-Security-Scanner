"""Judge captured behavioral evidence; these rules also work on saved offline snapshots."""

from __future__ import annotations

import re
from collections import defaultdict

from mcpiranha.core.models import (
    Category,
    Detector,
    DynamicObservation,
    Evidence,
    Finding,
    Location,
    Severity,
)
from mcpiranha.dynamic.constants import HOME, HONEY_PATHS
from mcpiranha.rules.base import Rule, RuleContext
from mcpiranha.rules.registry import register


@register
class HoneytokenRead(Rule):
    id = "MCP-DY-003"
    title = "Server accessed a synthetic credential file"
    category = Category.DYNAMIC
    default_severity = Severity.CRITICAL
    applies_to = frozenset({"tool"})
    remediation = "Remove the server or investigate why it accesses unrelated credentials."

    def run(self, ctx: RuleContext) -> list[Finding]:
        known = {f"{HOME}/{path}" for path in HONEY_PATHS}
        selected: dict[tuple[str, str, str | None], tuple[int, int, DynamicObservation]] = {}
        for i, event in enumerate(ctx.snapshot.observations):
            if event.kind not in ("file_open", "file_access") or event.readable is False:
                continue
            if event.success is False or (
                event.success is None and not re.search(r"= \d+(?:<|\s|$)", event.detail)
            ):
                continue
            if event.readable is None and any(
                flag in event.detail for flag in ("O_WRONLY", "O_PATH")
            ):
                continue
            token = event.honeytoken or event.path
            if token is None:
                token = next((path for path in known if f'{path}"' in event.detail), None)
            if token not in known:
                continue
            key = (token, event.phase, event.probe_id)
            strength = 2 if event.byte_count is not None else 1 if event.syscall == "mmap" else 0
            if key not in selected or strength > selected[key][0]:
                selected[key] = (strength, i, event)
        findings: list[Finding] = []
        for _, i, event in selected.values():
            access = (
                f"read {event.byte_count} byte(s) from a synthetic credential file. "
                if event.byte_count is not None
                else "mapped a synthetic credential file with read permission. "
                if event.syscall == "mmap"
                else "opened a synthetic credential file for reading. "
            )
            aliases = [
                Evidence(text=alias.detail)
                for alias in ctx.snapshot.observations
                if alias.kind == "file_alias"
                and alias.path == event.path
                and alias.honeytoken == event.honeytoken
            ][:1]
            findings.append(
                self.finding(
                    location=Location(
                        server_id=ctx.snapshot.id,
                        tool=event.tool,
                        json_pointer=f"/observations/{i}",
                    ),
                    evidence=[Evidence(text=event.detail), *aliases],
                    rationale=f"During {event.phase}, the server {access}"
                    "No real credentials were seeded."
                    + (
                        f" Temporally associated with probe {event.probe_id}."
                        if event.probe_id
                        else ""
                    ),
                    severity=Severity.HIGH if event.phase == "invocation" else Severity.CRITICAL,
                ).model_copy(update={"detector": Detector.DYNAMIC})
            )
        return findings


@register
class NetworkActivity(Rule):
    id = "MCP-DY-004"
    title = "Server attempted network access"
    category = Category.DYNAMIC
    default_severity = Severity.HIGH
    applies_to = frozenset({"tool"})
    remediation = "Review the destination and keep egress denied unless it is necessary."

    def run(self, ctx: RuleContext) -> list[Finding]:
        groups: dict[tuple[bool, str | None, str | None], list[DynamicObservation]] = defaultdict(
            list
        )
        for event in ctx.snapshot.observations:
            if event.kind in ("net_connect", "dns_lookup") and not event.infrastructure:
                groups[event.expected, event.tool, event.probe_id].append(event)
        findings: list[Finding] = []
        for (expected, tool, probe_id), events in groups.items():
            severity = (
                Severity.INFO
                if expected
                else (
                    Severity.HIGH
                    if any(o.phase != "invocation" for o in events)
                    else Severity.MEDIUM
                )
            )
            findings.append(
                self.finding(
                    location=Location(server_id=ctx.snapshot.id, tool=tool),
                    evidence=[Evidence(text=o.detail) for o in events[:10]],
                    rationale=(
                        "Operator-declared destination activity"
                        if expected
                        else "Unexpected network attempts"
                    )
                    + " (not proof of exfiltration): "
                    + "; ".join(dict.fromkeys(f"{o.phase}: {o.detail}" for o in events[:10]))
                    + (f". Temporally associated with probe {probe_id}." if probe_id else ""),
                    severity=severity,
                ).model_copy(update={"detector": Detector.DYNAMIC})
            )
        return findings


@register
class ChildProcess(Rule):
    id = "MCP-DY-005"
    title = "Server launched a shell or command interpreter"
    category = Category.DYNAMIC
    default_severity = Severity.MEDIUM
    applies_to = frozenset({"tool"})
    remediation = "Review whether invoking a command interpreter is required by this server."

    def run(self, ctx: RuleContext) -> list[Finding]:
        events = [
            o
            for o in ctx.snapshot.observations
            if o.kind == "process_spawn"
            and re.search(r'execve\("[^" ]*/(?:ba|da|z|k)?sh"', o.detail)
            and re.search(r"= 0(?:\s|$)", o.detail)
        ]
        groups: dict[tuple[str | None, str | None], list[DynamicObservation]] = defaultdict(list)
        for event in events:
            groups[event.tool, event.probe_id].append(event)
        return [
            self.finding(
                location=Location(server_id=ctx.snapshot.id, tool=tool),
                evidence=[Evidence(text=o.detail) for o in group[:5]],
                rationale="A command interpreter was executed: "
                + "; ".join(o.detail for o in group[:5])
                + (f". Temporally associated with probe {probe_id}." if probe_id else ""),
            ).model_copy(update={"detector": Detector.DYNAMIC})
            for (tool, probe_id), group in groups.items()
        ]


@register
class FuzzSink(Rule):
    id = "MCP-DY-006"
    title = "Fuzz probe reached a behavioral canary"
    category = Category.DYNAMIC
    default_severity = Severity.MEDIUM
    applies_to = frozenset({"tool"})
    remediation = "Inspect the handler and intended permissions to determine exploitability."

    def run(self, ctx: RuleContext) -> list[Finding]:
        probes = {p.id: p for p in ctx.snapshot.probes}
        findings: dict[str, tuple[int, Finding]] = {}
        for i, event in enumerate(ctx.snapshot.observations):
            probe = probes.get(event.probe_id or "")
            if probe is None or probe.variant == "baseline":
                continue
            hit = (
                (
                    probe.variant == "path_traversal"
                    and event.kind in ("file_open", "file_access")
                    and (
                        event.path == "/tmp/mcpiranha-canary"
                        or event.honeytoken == "/tmp/mcpiranha-canary"
                    )
                    and event.success is True
                    and event.readable is not False
                )
                or (
                    probe.variant == "shell_injection"
                    and event.kind == "process_spawn"
                    and event.success is True
                    and re.search(r'execve\("[^" ]*/(?:ba|da|z|k)?sh"', event.detail)
                    and "MCPIRANHA_FUZZ" in event.detail
                )
                or (
                    probe.variant == "ssrf"
                    and event.kind in ("net_connect", "dns_lookup")
                    and event.destination == "192.0.2.1:80"
                )
            )
            if hit:
                strength = (
                    2 if event.byte_count is not None else 1 if event.syscall == "mmap" else 0
                )
                if probe.id in findings and strength <= findings[probe.id][0]:
                    continue
                finding = self.finding(
                    location=Location(
                        server_id=ctx.snapshot.id,
                        tool=probe.tool,
                        json_pointer=f"/observations/{i}",
                    ),
                    evidence=[Evidence(text=event.detail)],
                    rationale=f"Probe {probe.id} ({probe.variant}, {probe.argument_path}) "
                    "coincided with access to its canary. This is temporal evidence of "
                    "a reachable sink; intended permissions determine exploitability.",
                ).model_copy(update={"detector": Detector.DYNAMIC})
                findings[probe.id] = (strength, finding)
        return [finding for _, finding in findings.values()]


@register
class TraceInterference(Rule):
    id = "MCP-DY-007"
    title = "Server attempted to interfere with the tracing collector"
    category = Category.DYNAMIC
    default_severity = Severity.HIGH
    applies_to = frozenset({"tool"})
    remediation = "Investigate the process-control attempt before trusting the server."

    def run(self, ctx: RuleContext) -> list[Finding]:
        return [
            self.finding(
                location=Location(
                    server_id=ctx.snapshot.id, tool=event.tool, json_pointer=f"/observations/{i}"
                ),
                evidence=[Evidence(text=event.detail)],
                rationale="The server attempted to signal or trace a protected collector process. "
                "The syscall result records whether the attempt was denied.",
            ).model_copy(update={"detector": Detector.DYNAMIC})
            for i, event in enumerate(ctx.snapshot.observations)
            if event.kind == "trace_tamper"
        ]

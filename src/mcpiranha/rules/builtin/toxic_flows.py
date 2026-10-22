"""MCP-TF-001 / MCP-TF-002: dangerous combinations across the tools one agent can use.

Each server can be harmless on its own and still complete an attack together with the others in
the same client. The agent reads something an attacker wrote (an issue, a web page, an email);
injected instructions in it then use the agent's other tools.

- TF-001, the "lethal trifecta": untrusted content + private data + a way to send data out. One
  poisoned issue can make the agent read your files and post them somewhere.
- TF-002: untrusted content + code execution or destructive tools: injection becomes remote code
  execution or data loss.

Combinations inside one server are reported at lower severity (they are what the server is for,
e.g. a browser server that also runs JavaScript); combinations across servers are what people
don't realize they've built. Auto-approved tools raise the severity: nothing stops the chain.
Each chain is reported once per client, on the server that brings in the untrusted content.
"""

from __future__ import annotations

from collections.abc import Sequence
from itertools import product

from mcpiranha.core.models import (
    CapabilityLabel,
    Category,
    Confidence,
    Evidence,
    Finding,
    Location,
    Severity,
)
from mcpiranha.flows import ToolCapabilities, inventory_capabilities
from mcpiranha.rules.base import Rule, RuleContext
from mcpiranha.rules.registry import register

L = CapabilityLabel
_UNTRUSTED, _PRIVATE, _OUTBOUND = (
    L.INGESTS_UNTRUSTED_CONTENT, L.READS_PRIVATE_DATA, L.EXTERNAL_COMMUNICATION,
)  # fmt: skip


def _with(caps: Sequence[ToolCapabilities], label: CapabilityLabel) -> list[ToolCapabilities]:
    return [c for c in caps if label in c.labels]


def best_chain(*legs: list[ToolCapabilities]) -> tuple[ToolCapabilities, ...] | None:
    """The most telling chain: the most distinct servers, then distinct tools, then name order."""
    if not all(legs):
        return None
    candidates = product(*(sorted(leg, key=lambda c: c.qualified)[:20] for leg in legs))
    return max(
        candidates,
        key=lambda chain: (len({c.server_id for c in chain}), len({c.qualified for c in chain})),
    )


def _describe(
    chain: Sequence[ToolCapabilities], roles: Sequence[tuple[str, CapabilityLabel]]
) -> str:
    steps = [
        f"{c.qualified} ({role})" if c.known else f"{c.qualified} ({role}: {c.labels[label]})"
        for c, (role, label) in zip(chain, roles, strict=True)
    ]
    return " -> ".join(steps)


class _FlowRule(Rule):
    category = Category.TOXIC_FLOW
    applies_to = frozenset({"tool", "config"})

    def _report(
        self,
        ctx: RuleContext,
        chain: tuple[ToolCapabilities, ...],
        roles: list[tuple[str, CapabilityLabel]],
        what: str,
        cross_server: Severity,
        same_server: Severity,
    ) -> list[Finding]:
        if ctx.snapshot.id != chain[0].server_id:
            return []  # reported once, on the server that brings in the untrusted content
        servers = {c.server_id for c in chain}
        severity = cross_server if len(servers) > 1 else same_server
        approved = [c.qualified for c in chain[1:] if c.auto_approved]
        rationale = f"{what}: {_describe(chain, roles)}."
        if len(servers) == 1:
            rationale += " All within one server, so this is likely by design; still a risk."
        if approved:
            severity = Severity.CRITICAL if len(servers) > 1 else Severity.HIGH
            rationale += f" Auto-approved, so nothing asks first: {', '.join(approved)}."
        if any(c.known for c in chain):
            rationale += " (Some capabilities come from mcpiranha's table of well-known servers.)"
        return [
            self.finding(
                location=Location(
                    server_id=chain[0].server_id,
                    tool=chain[0].tool,
                    file=ctx.snapshot.origin.config_path,
                ),
                evidence=[Evidence(text=c.qualified) for c in chain],
                rationale=rationale,
                severity=severity,
                confidence=Confidence.MEDIUM,  # labels are heuristics
            )
        ]


@register
class LethalTrifecta(_FlowRule):
    id = "MCP-TF-001"
    title = "Untrusted input, private data and an outbound channel in one agent"
    default_severity = Severity.HIGH
    remediation = (
        "Split these servers across separate clients or profiles, or remove one leg: the "
        "untrusted-content source, the private-data access, or the ability to send data out. "
        "At least keep confirmation on for the outbound tool."
    )
    references = ("https://simonwillison.net/2025/Jun/16/the-lethal-trifecta/",)

    def run(self, ctx: RuleContext) -> list[Finding]:
        caps = inventory_capabilities(ctx.inventory)
        chain = best_chain(_with(caps, _UNTRUSTED), _with(caps, _PRIVATE), _with(caps, _OUTBOUND))
        if chain is None:
            return []
        roles = [("untrusted input", _UNTRUSTED), ("private data", _PRIVATE),
                 ("sends out", _OUTBOUND)]  # fmt: skip
        return self._report(ctx, chain, roles,
                            "Injected content can read private data and send it out",
                            Severity.HIGH, Severity.MEDIUM)  # fmt: skip


@register
class InjectionToExecution(_FlowRule):
    id = "MCP-TF-002"
    title = "Untrusted input and code execution or destructive tools in one agent"
    default_severity = Severity.HIGH
    remediation = (
        "Don't combine tools that read attacker-controlled content with tools that run code or "
        "delete things in the same client, or keep confirmation on for the latter."
    )

    def run(self, ctx: RuleContext) -> list[Finding]:
        caps = inventory_capabilities(ctx.inventory)
        untrusted = _with(caps, _UNTRUSTED)
        findings: list[Finding] = []
        for label, role, what, cross, same in (
            (L.EXECUTES_CODE, "runs code", "Injected content can run code",
             Severity.HIGH, Severity.LOW),
            (L.DESTRUCTIVE, "destroys", "Injected content can delete or destroy data",
             Severity.MEDIUM, Severity.LOW),
        ):  # fmt: skip
            chain = best_chain(untrusted, _with(caps, label))
            if chain and chain[0].qualified != chain[1].qualified:
                roles = [("untrusted input", _UNTRUSTED), (role, label)]
                findings += self._report(ctx, chain, roles, what, cross, same)
        return findings

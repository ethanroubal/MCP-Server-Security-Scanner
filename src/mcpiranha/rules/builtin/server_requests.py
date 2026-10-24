"""MCP-DY-001 / MCP-DY-002: the server sent the client requests while it was only being listed.

A server can ask the client to run its model (sampling), list the workspace roots, or ask the
user for input (elicitation). Inside a tool call, on request, these can be legitimate. During a
plain listing (or while serving a prompt or resource read), with no tool called, they're the
server acting on its own: spending the user's model, mapping their workspace, or phishing.
mcpiranha declines every such request (acquire/listing.py) and records it.
"""

from __future__ import annotations

import re

from mcpiranha.core.models import Category, Confidence, Evidence, Finding, Location, Severity
from mcpiranha.rules.base import Rule, RuleContext
from mcpiranha.rules.registry import register

_SECRET_ASK = re.compile(
    r"password|passphrase|passcode|\bpin\b|token|api[ _-]?key|secret|credential|private key|"
    r"seed phrase|recovery phrase|mnemonic|2fa|one[- ]time code|otp|ssn|social security|"
    r"card number|cvv",
    re.IGNORECASE,
)


@register
class UnpromptedRequests(Rule):
    id = "MCP-DY-001"
    title = "Server used the client's model or asked for its roots unprompted"
    category = Category.DYNAMIC
    default_severity = Severity.MEDIUM
    applies_to = frozenset({"tool", "prompt", "resource"})
    remediation = (
        "Nothing was called, yet the server asked the client to generate text with the user's "
        "model (sampling) or to reveal the workspace roots. Deny sampling to this server in the "
        "client, or remove it."
    )

    def run(self, ctx: RuleContext) -> list[Finding]:
        seen = [
            o
            for o in ctx.snapshot.observations
            if o.phase != "invocation" and o.kind in ("sampling_request", "roots_request")
        ]
        if not seen:
            return []
        sampling = any(o.kind == "sampling_request" for o in seen)
        return [self.finding(
            location=Location(server_id=ctx.snapshot.id),
            evidence=[Evidence(text=o.detail) for o in seen[:5]],
            rationale="While only being listed, the server " + "; ".join(
                dict.fromkeys(o.detail for o in seen)) + ".",
            severity=Severity.MEDIUM if sampling else Severity.LOW,
            confidence=Confidence.HIGH,
        )]  # fmt: skip


@register
class UnpromptedElicitation(Rule):
    id = "MCP-DY-002"
    title = "Server asked the user for input unprompted"
    category = Category.DYNAMIC
    default_severity = Severity.MEDIUM
    applies_to = frozenset({"tool", "prompt", "resource"})
    remediation = (
        "A server that asks for passwords, tokens or keys through the client is phishing: "
        "credentials belong in the server's configuration, set by you. Don't answer, and "
        "remove the server."
    )

    def run(self, ctx: RuleContext) -> list[Finding]:
        seen = [
            o
            for o in ctx.snapshot.observations
            if o.phase != "invocation" and o.kind == "elicitation_request"
        ]
        if not seen:
            return []
        secret = any(_SECRET_ASK.search(o.detail) for o in seen)
        return [self.finding(
            location=Location(server_id=ctx.snapshot.id),
            evidence=[Evidence(text=o.detail) for o in seen[:5]],
            rationale="While only being listed, the server " + "; ".join(
                dict.fromkeys(o.detail for o in seen)) + (
                ". It asks for secrets." if secret else "."),
            severity=Severity.HIGH if secret else Severity.MEDIUM,
            confidence=Confidence.HIGH,
        )]  # fmt: skip

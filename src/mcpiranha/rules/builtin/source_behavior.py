"""MCP-SRC: what the server's code does that its tools don't say.

Judged on what `mcpiranha.source` found in the code the server runs (a local script, or the npm /
PyPI release, read without running it). These look for malicious behavior hidden behind honest
metadata, the case no metadata rule can see:

- SRC-001: a fixed email address added as Bcc/Cc (postmark-mcp copied every email it sent).
- SRC-002: collecting the environment's secrets (serializing it, or picking TOKEN/KEY variables).
- SRC-003: literal paths to credential stores (~/.ssh, ~/.aws/credentials, browser logins), in
  code that also has a way out (SRC-001, -002 or -005). Alone they're common and benign: SSH
  tunnels read ~/.ssh/id_rsa, security tools list these paths to block them.
- SRC-004: running decoded or downloaded code (eval(atob(...)), exec(b64decode(...))). Not
  `curl | sh` strings: calibration found them only in install instructions and deny-lists.
- SRC-005: a hardcoded request catcher, tunnel or Discord webhook as a destination.

One finding per rule and server, citing up to five places.
"""

from __future__ import annotations

from mcpiranha.core.models import (
    Category,
    Confidence,
    Evidence,
    Finding,
    Location,
    Severity,
    SourceHit,
    SourceHitKind,
)
from mcpiranha.rules.base import Rule, RuleContext
from mcpiranha.rules.registry import register

SHOWN = 5


class _SourceRule(Rule):
    category = Category.SOURCE
    applies_to = frozenset({"source"})
    kinds: tuple[SourceHitKind, ...]
    what: str
    confidence = Confidence.MEDIUM

    def run(self, ctx: RuleContext) -> list[Finding]:
        tree = ctx.snapshot.source
        hits = [h for h in tree.hits if h.kind in self.kinds] if tree else []
        if not tree or not hits:
            return []
        places = "; ".join(f"{h.file}:{h.line} {h.detail}" for h in hits[:SHOWN])
        more = f" (and {len(hits) - SHOWN} more)" if len(hits) > SHOWN else ""
        first = hits[0]
        return [self.finding(
            location=Location(server_id=ctx.snapshot.id, file=_file(tree.root, first),
                              line=first.line),
            evidence=[Evidence(text=h.code) for h in hits[:SHOWN] if h.code],
            rationale=f"{self.what} in {tree.root}: {places}{more}.",
            confidence=self.confidence,
        )]  # fmt: skip


def _file(root: str, hit: SourceHit) -> str:
    return f"{root}/{hit.file}" if not hit.file.startswith("/") else hit.file


@register
class HiddenRecipient(_SourceRule):
    id = "MCP-SRC-001"
    title = "Code adds a fixed Bcc/Cc recipient"
    default_severity = Severity.HIGH
    kinds = ("hardcoded_recipient",)
    what = "The code sends copies of messages to a fixed address"
    confidence = Confidence.HIGH
    remediation = (
        "Nothing in a mail tool's description says copies go elsewhere. Unless the server's "
        "purpose explains it, treat every message sent through it as leaked, and remove it."
    )
    references = ("https://www.koi.ai/blog/postmark-mcp-npm-malicious-backdoor-email-theft",)


@register
class EnvHarvest(_SourceRule):
    id = "MCP-SRC-002"
    title = "Code collects secrets from the environment"
    default_severity = Severity.HIGH
    kinds = ("env_harvest",)
    what = "The code collects environment variables wholesale or by secret-looking names"
    remediation = (
        "A server needs the variables its config sets, by name. Collecting all of them, or "
        "every TOKEN / KEY, is how credential stealers start; rotate what it could see."
    )


@register
class CredentialPaths(_SourceRule):
    id = "MCP-SRC-003"
    title = "Code names credential files and has a way to send data out"
    default_severity = Severity.HIGH
    kinds = ("sensitive_file",)
    what = "The code names credential stores, and also sends data to a fixed destination"
    remediation = (
        "Credential paths next to a hardcoded destination is the shape of a stealer. Don't run "
        "it, and rotate the credentials if it already ran."
    )
    _OUT: tuple[SourceHitKind, ...] = ("exfil_host", "hardcoded_recipient", "env_harvest")

    def run(self, ctx: RuleContext) -> list[Finding]:
        tree = ctx.snapshot.source
        if tree is None or not any(h.kind in self._OUT for h in tree.hits):
            return []
        return super().run(ctx)


@register
class HiddenCode(_SourceRule):
    id = "MCP-SRC-004"
    title = "Code runs decoded or downloaded code"
    default_severity = Severity.HIGH
    kinds = ("dynamic_code",)
    what = "The code runs code it decodes or downloads"
    remediation = (
        "Code that only exists after decoding or downloading can't be reviewed, and can change "
        "without a release. Don't run the server until you know what it executes."
    )


@register
class ExfilEndpoint(_SourceRule):
    id = "MCP-SRC-005"
    title = "Code contains a request-catcher or webhook address"
    default_severity = Severity.HIGH
    kinds = ("exfil_host",)
    what = "The code has a hardcoded data-collection endpoint"
    remediation = (
        "Request catchers, tunnels and webhook URLs are where stolen data is sent; a server "
        "that posts to your own webhook takes its URL as configuration, not as a literal."
    )

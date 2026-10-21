"""MCP-CF-001: secrets stored in plaintext in a client config.

Client configs are often synced, backed up, shared in screenshots or committed (`.mcp.json`,
`.vscode/mcp.json`). A token written into one is exposed to all of that.

Reports never contain the secret: evidence is the env var, header or flag *name*, and the
rationale shows only the token type, its non-secret prefix and its length.
"""

from __future__ import annotations

from mcpscan.core.models import Category, Confidence, Evidence, Finding, Location, Severity
from mcpscan.core.secrets import classify, secret_candidates
from mcpscan.rules.base import Rule, RuleContext
from mcpscan.rules.registry import register


def _article(word: str) -> str:
    return "an" if word[:1].lower() in "aeiou" else "a"


@register
class ConfigSecrets(Rule):
    id = "MCP-CF-001"
    title = "Plaintext secret in client config"
    category = Category.CONFIG
    default_severity = Severity.HIGH
    applies_to = frozenset({"config"})
    remediation = (
        "Move the secret out of the config file: reference an environment variable (most clients "
        "expand ${VAR}) or a secret manager instead. If this file was ever shared, synced or "
        "committed, rotate the secret."
    )

    def run(self, ctx: RuleContext) -> list[Finding]:
        launch = ctx.snapshot.launch
        if launch is None:
            return []
        where = ctx.snapshot.origin.config_path or ctx.snapshot.origin.ref
        findings: list[Finding] = []
        for name, value, pointer in secret_candidates(launch):
            if (hit := classify(name, value)) is None:
                continue
            label, prefix, confidence = hit
            shown = f"{value.strip()[:prefix]}… " if prefix else ""
            findings.append(
                self.finding(
                    location=Location(
                        server_id=ctx.snapshot.id,
                        json_pointer=pointer,
                        file=ctx.snapshot.origin.config_path,
                    ),
                    evidence=[Evidence(text=name)],
                    rationale=f"{name} holds {_article(label)} {label} "
                    f"({shown}{len(value.strip())} chars) in plaintext in {where}.",
                    severity=Severity.HIGH if confidence is Confidence.HIGH else Severity.MEDIUM,
                    confidence=confidence,
                )
            )
        return findings

"""MCP-TP-005: references to credentials, keys and other sensitive files.

A calculator or weather tool has no reason to mention `~/.ssh/id_rsa`, `.env` or the client's own
MCP config. Poisoned descriptions name these files so the model reads them and passes them on.
"""

from __future__ import annotations

import re

from mcpscan.core.matching import MatchView, carries_hidden_text
from mcpscan.core.models import Category, Evidence, Finding, Severity
from mcpscan.core.text import iter_text_fields
from mcpscan.rules.base import Rule, RuleContext
from mcpscan.rules.registry import register

_I = re.IGNORECASE
_B = r"(?<![\w.-])"  # start boundary that still allows a leading "~/", "/" or quote

# (pattern, label)
_SENSITIVE: tuple[tuple[re.Pattern[str], str], ...] = (
    (re.compile(r"\.ssh\b|\bid_(rsa|dsa|ecdsa|ed25519)\b|\bauthorized_keys\b|\bknown_hosts\b", _I),
     "SSH keys"),
    (re.compile(r"\.aws/(credentials|config)\b|\.azure/|\.config/gcloud\b|"
                r"application_default_credentials\.json", _I), "cloud credentials"),
    (re.compile(_B + r"\.env(\.[a-z]+)?\b", _I), "dotenv file"),
    (re.compile(r"\.(npmrc|pypirc|netrc|git-credentials)\b|\.docker/config\.json|\.kube/config\b|"
                r"\.gnupg\b", _I), "tool credentials"),
    (re.compile(r"\bmcp\.json\b|claude_desktop_config\.json|\.claude\.json|\.cursor/|"
                r"mcp_config\.json", _I), "MCP client config"),
    (re.compile(r"/etc/(passwd|shadow|sudoers)\b", _I), "system account files"),
    (re.compile(r"\b(Login Data|Cookies\.sqlite|key[34]\.db|logins\.json)\b|"
                r"\bkeychain\b|\bwallet\.dat\b|\bseed\s+phrase\b", _I),
     "browser or wallet secrets"),
    (re.compile(r"\b(private|secret)[ _-]?keys?\b", _I), "private keys"),
)  # fmt: skip


@register
class SensitivePaths(Rule):
    id = "MCP-TP-005"
    title = "References to credentials or sensitive files"
    category = Category.TOOL_POISONING
    default_severity = Severity.HIGH
    applies_to = frozenset({"tool", "prompt", "resource"})
    remediation = (
        "Check why this tool's metadata names sensitive files. Unless the tool genuinely manages "
        "them (and you expected that), it is likely trying to get the model to read and leak them."
    )

    def run(self, ctx: RuleContext) -> list[Finding]:
        findings: list[Finding] = []
        for tf in iter_text_fields(ctx.snapshot):
            if tf.kind in ("name", "uri", "property-name"):
                continue
            view = MatchView.of(tf.text)
            hits: list[tuple[str, Evidence]] = [
                (label, evidence)
                for pattern, label in _SENSITIVE
                for _, evidence in view.finditer(pattern)
            ]
            if not hits:
                continue
            hidden = any(carries_hidden_text(ev.text) for _, ev in hits)
            rationale = f"The {tf.kind} references {', '.join(sorted({lb for lb, _ in hits}))}."
            if hidden:
                rationale += " The reference is hidden in invisible characters."
            findings.append(
                self.finding(
                    location=tf.location,
                    evidence=[ev for _, ev in hits],
                    rationale=rationale,
                    severity=Severity.CRITICAL if hidden else Severity.HIGH,
                )
            )
        return findings

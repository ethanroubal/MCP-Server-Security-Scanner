"""MCP-TP-002: terminal escape sequences and other control characters in metadata.

CLI clients print tool descriptions in approval prompts. ANSI/OSC sequences can hide text (conceal,
black-on-black), move the cursor to overwrite what was shown, or create misleading hyperlinks.
"""

from __future__ import annotations

import re

from mcpiranha.core.models import Category, Evidence, Finding, Severity
from mcpiranha.core.text import iter_text_fields
from mcpiranha.rules.base import Rule, RuleContext
from mcpiranha.rules.registry import register

_ESCAPE = re.compile(
    r"\x1b\[[0-9;?]*[ -/]*[@-~]"  # CSI: colors, conceal, cursor movement, erase
    r"|\x1b\][^\x07\x1b]*(?:\x07|\x1b\\)?"  # OSC: window title, hyperlinks
    r"|\x1b[@-Z\\-_]"  # other two-byte escapes
    r"|\x9b[0-9;?]*[ -/]*[@-~]"  # 8-bit CSI
)
_OTHER_CONTROL = re.compile(r"[\x00-\x08\x0b\x0c\x0e-\x1a\x1c-\x1f\x7f]+")


@register
class TerminalEscapes(Rule):
    id = "MCP-TP-002"
    title = "Terminal escape sequences"
    category = Category.TOOL_POISONING
    default_severity = Severity.HIGH
    applies_to = frozenset({"tool", "prompt", "resource"})
    remediation = (
        "Strip control characters from the metadata. Escape sequences have no legitimate place in "
        "a tool description and can hide text from you in terminal-based clients."
    )

    def run(self, ctx: RuleContext) -> list[Finding]:
        findings: list[Finding] = []
        for tf in iter_text_fields(ctx.snapshot):
            escapes = list(_ESCAPE.finditer(tf.text))
            controls = list(_OTHER_CONTROL.finditer(tf.text))
            if not escapes and not controls:
                continue
            evidence = [
                Evidence(text=m.group(), start=m.start(), end=m.end())
                for m in sorted([*escapes, *controls], key=lambda m: m.start())
            ]
            if escapes:
                rationale = (
                    f"{len(escapes)} terminal escape sequence(s) in the {tf.kind}. In a terminal "
                    "they can hide text or overwrite what is displayed."
                )
            else:
                rationale = f"{len(controls)} unexpected control character run(s) in the {tf.kind}."
            findings.append(
                self.finding(
                    location=tf.location,
                    evidence=evidence,
                    rationale=rationale,
                    severity=Severity.HIGH if escapes else Severity.LOW,
                )
            )
        return findings

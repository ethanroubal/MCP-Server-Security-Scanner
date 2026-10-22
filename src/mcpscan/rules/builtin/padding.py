"""MCP-TP-008: whitespace padding that pushes a payload out of view.

Approval dialogs show the first part of a description. Long runs of spaces or blank lines push the
real payload out of view. Calibration found plenty of indented formatting in legitimate long
descriptions, so padding is only reported when the text after it is itself suspicious.
"""

from __future__ import annotations

import re

from mcpscan.core.models import Category, Evidence, Finding, Severity
from mcpscan.core.text import iter_text_fields
from mcpscan.rules.base import Rule, RuleContext
from mcpscan.rules.builtin.sensitive_paths import is_suspicious
from mcpscan.rules.registry import register

_SPACE_RUN = re.compile(r"[^\S\n]{40,}")  # any whitespace except newline, Unicode spaces included
_BLANK_LINES = re.compile(r"(?:[^\S\n]*\n){8,}")


@register
class Padding(Rule):
    id = "MCP-TP-008"
    title = "Whitespace padding or oversized description"
    category = Category.TOOL_POISONING
    default_severity = Severity.MEDIUM
    applies_to = frozenset({"tool", "prompt", "resource"})
    remediation = (
        "Read the full text, including what comes after the padding: clients often show only the "
        "beginning of a description."
    )

    def run(self, ctx: RuleContext) -> list[Finding]:
        findings: list[Finding] = []
        for tf in iter_text_fields(ctx.snapshot):
            runs = [*_SPACE_RUN.finditer(tf.text), *_BLANK_LINES.finditer(tf.text)]
            if not runs:
                continue
            tail = tf.text[max(m.end() for m in runs) :]
            if not tail.strip() or not is_suspicious(tail):
                continue
            findings.append(
                self.finding(
                    location=tf.location,
                    evidence=[Evidence(text=m.group(), start=m.start(), end=m.end()) for m in runs],
                    rationale=f"{len(runs)} long whitespace run(s) in the {tf.kind} push "
                    f"{len(tail)} character(s) of suspicious text out of view.",
                    severity=Severity.HIGH,
                )
            )
        return findings

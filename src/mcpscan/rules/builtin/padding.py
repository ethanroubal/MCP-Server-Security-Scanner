"""MCP-TP-008: whitespace padding and oversized descriptions.

Approval dialogs show the first part of a description. Long runs of spaces or blank lines push the
real payload out of view; extremely long descriptions are hard to review at all.
"""

from __future__ import annotations

import re

from mcpscan.core.models import Category, Evidence, Finding, Severity
from mcpscan.core.text import iter_text_fields
from mcpscan.rules.base import Rule, RuleContext
from mcpscan.rules.registry import register

_SPACE_RUN = re.compile(r"[^\S\n]{40,}")  # any whitespace except newline, Unicode spaces included
_BLANK_LINES = re.compile(r"(?:[^\S\n]*\n){8,}")
MAX_DESCRIPTION_CHARS = 4000


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
            if runs:
                after = len(tf.text) - max(m.end() for m in runs)
                findings.append(
                    self.finding(
                        location=tf.location,
                        evidence=[
                            Evidence(text=m.group(), start=m.start(), end=m.end()) for m in runs
                        ],
                        rationale=f"{len(runs)} long whitespace run(s) in the {tf.kind}, followed "
                        f"by {after} more character(s) that may be scrolled out of view.",
                        severity=Severity.MEDIUM if after else Severity.LOW,
                    )
                )
            elif (
                tf.kind in ("description", "instructions") and len(tf.text) > MAX_DESCRIPTION_CHARS
            ):
                findings.append(
                    self.finding(
                        location=tf.location,
                        evidence=[Evidence(text=tf.text[:80], start=0, end=min(80, len(tf.text)))],
                        rationale=f"The {tf.kind} is {len(tf.text)} characters long, which is "
                        "hard to review fully.",
                        severity=Severity.LOW,
                    )
                )
        return findings

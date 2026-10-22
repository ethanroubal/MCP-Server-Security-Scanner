"""MCP-TP-003: markup that imitates system or chat-template structure.

`<IMPORTANT>`, `<system>`, `[INST]`, `<|im_start|>` and similar make injected text look like it
carries more authority than a tool description. HTML comments hide text from rendered views.
Ordinary XML-style structure (`<example>`, `<usage>`) is fine and is not flagged.
"""

from __future__ import annotations

import re

from mcpscan.core.matching import MatchView
from mcpscan.core.models import Category, Evidence, Finding, Severity
from mcpscan.core.text import iter_text_fields
from mcpscan.rules.base import Rule, RuleContext
from mcpscan.rules.builtin.sensitive_paths import is_suspicious
from mcpscan.rules.registry import register

_I = re.IGNORECASE

# (pattern, severity, label)
_MARKUP: tuple[tuple[re.Pattern[str], Severity, str], ...] = (
    (re.compile(r"<\s*/?\s*(important|system|secret|hidden|override|admin|critical|urgent)\b"
                r"[^<>]{0,80}>", _I), Severity.HIGH, "authority tag"),
    (re.compile(r"<\s*/?\s*(instructions?|assistant|developer|system[_-]?prompt)\b[^<>]{0,80}>",
                _I), Severity.MEDIUM, "instruction tag"),
    (re.compile(r"\[/?(inst|sys)\]", _I), Severity.HIGH, "Llama instruction marker"),
    (re.compile(r"<<\s*/?\s*sys\s*>>", _I), Severity.HIGH, "Llama system marker"),
    (re.compile(r"<\|\s*(im_start|im_end|system|user|assistant|endoftext|eot_id|start_header_id|"
                r"end_header_id)\s*\|>", _I), Severity.HIGH, "chat-template token"),
    (re.compile(r"<!--.*?(-->|$)", re.DOTALL), Severity.MEDIUM, "HTML comment"),
    (re.compile(r"^[ \t]*#{1,6}[ \t]*(system|instructions?|important)\b", _I | re.MULTILINE),
     Severity.MEDIUM, "directive heading"),
)  # fmt: skip


@register
class DirectiveMarkup(Rule):
    id = "MCP-TP-003"
    title = "Directive markup imitating system instructions"
    category = Category.TOOL_POISONING
    default_severity = Severity.HIGH
    applies_to = frozenset({"tool", "prompt", "resource"})
    remediation = (
        "Remove the markup. Tags like <IMPORTANT> or <system> in a tool description are a common "
        "way to give injected instructions extra weight with the model."
    )

    def run(self, ctx: RuleContext) -> list[Finding]:
        findings: list[Finding] = []
        for tf in iter_text_fields(ctx.snapshot):
            if tf.kind in ("name", "uri", "property-name"):
                continue
            view = MatchView.of(tf.text)
            hits: list[tuple[Severity, str, Evidence]] = [
                (severity, label, evidence)
                for pattern, severity, label in _MARKUP
                for _, evidence in view.finditer(pattern)
            ]
            # Calibration: HTML comments in real descriptions hold example markup. Report one
            # only if what it hides is itself suspicious.
            hits = [h for h in hits if h[1] != "HTML comment" or is_suspicious(h[2].text)]
            if not hits:
                continue
            findings.append(
                self.finding(
                    location=tf.location,
                    evidence=sorted((ev for _, _, ev in hits), key=lambda ev: ev.start or 0),
                    rationale="Directive markup in the "
                    f"{tf.kind}: {', '.join(sorted({label for _, label, _ in hits}))}.",
                    severity=max((s for s, _, _ in hits), key=lambda s: s.rank),
                )
            )
        return findings

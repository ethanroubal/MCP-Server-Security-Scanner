"""MCP-TP-004: phrases that instruct the model, not describe the tool.

A tool description should say what the tool does. Text that tells the model what to do (ignore
earlier instructions, call something first, keep things from the user) is how tool poisoning works.
Phrases are weighted and summed per field, so one ambiguous word ("always", "important") is not
enough on its own.
"""

from __future__ import annotations

import re

from mcpscan.core.matching import MatchView, carries_hidden_text
from mcpscan.core.models import Category, Confidence, Evidence, Finding, Severity
from mcpscan.core.text import iter_text_fields
from mcpscan.rules.base import Rule, RuleContext
from mcpscan.rules.registry import register

_I = re.IGNORECASE

# (pattern, weight, label)
PHRASES: tuple[tuple[re.Pattern[str], int, str], ...] = (
    (re.compile(r"\b(ignore|disregard|forget|override)\s+(all\s+|any\s+)?(the\s+|your\s+)?"
                r"(previous|prior|above|earlier|other|original)\s+(instructions?|directions|rules"
                r"|guidelines|context|prompts?)", _I), 3, "override earlier instructions"),
    (re.compile(r"\b(new|updated|real|actual|secret|hidden)\s+instructions?\b", _I), 2,
     "claims new instructions"),
    (re.compile(r"\bbefore\s+(using|calling|invoking|running|you\s+(use|call))\s+(this|the|any)\s+"
                r"(tool|function)", _I), 2, "pre-condition on tool use"),
    (re.compile(r"\b(do\s+not|don't|dont|never|without)\s+(ever\s+)?(tell(ing)?|mention(ing)?|"
                r"inform(ing)?|reveal(ing)?|notify(ing)?|disclos(e|ing)|alert(ing)?|let)\b", _I), 2,
     "conceal from the user"),
    (re.compile(r"\b(the\s+user\s+(must|should)\s+not|hide\s+(this|it)\s+from)\b", _I), 2,
     "conceal from the user"),
    (re.compile(r"\byou\s+(must|should|need\s+to|have\s+to)\s+(always\s+|first\s+)*(call|use|"
                r"invoke|read|send|include|pass|set|add|run|execute|forward)\b", _I), 2,
     "commands the model"),
    (re.compile(r"\balways\s+(call|use|invoke|set|add|include|send|pass|bcc|cc|forward|run|"
                r"execute|copy)\b", _I), 2, "commands the model"),
    (re.compile(r"\b(when|whenever|if|after|each\s+time)\b[^.\n]{0,60}\b(tool|function)\s+is\s+"
                r"(used|called|invoked|run)", _I), 2, "hooks another tool's use"),
    (re.compile(r"\b(otherwise|or\s+else)\b[^.\n]{0,30}\b(will\s+not|won't|will\s+fail|fails|"
                r"cannot|can't)\s+(work|run|function)", _I), 2, "threat to make the model comply"),
    (re.compile(r"\b(this\s+is|it\s+is)\s+(very\s+|extremely\s+)?(important|required|mandatory|"
                r"critical|essential)\b", _I), 1, "urgency"),
    (re.compile(r"\binclude\s+(the\s+|its\s+|their\s+)?(full\s+)?(output|contents?|results?|"
                r"response)\s+(of|from|in)\b", _I), 1, "asks to relay data"),
    (re.compile(r"\bsystem\s+prompt\b", _I), 1, "mentions the system prompt"),
    (re.compile(r"\b(act|behave|respond)\s+as\s+(if\s+you\s+are\s+|an?\s+)?(admin|administrator|"
                r"developer|system|root)\b", _I), 2, "role override"),
)  # fmt: skip

THRESHOLD = 3
HIGH_SCORE = 5


def instruction_matches(view: MatchView) -> tuple[int, list[tuple[str, Evidence]]]:
    """Total weight and (label, evidence) for every phrase match in the view."""
    score = 0
    matches: list[tuple[str, Evidence]] = []
    for pattern, weight, label in PHRASES:
        for _, evidence in view.finditer(pattern):
            score += weight
            matches.append((label, evidence))
    return score, matches


@register
class InstructionPhrases(Rule):
    id = "MCP-TP-004"
    title = "Instructions aimed at the model"
    category = Category.TOOL_POISONING
    default_severity = Severity.MEDIUM
    applies_to = frozenset({"tool", "prompt", "resource"})
    remediation = (
        "Tool metadata should only describe what the tool does. Review the quoted text: if the "
        "server's author didn't put it there on purpose, treat the server as compromised."
    )
    references = ("https://invariantlabs.ai/blog/mcp-security-notification-tool-poisoning-attacks",)

    def run(self, ctx: RuleContext) -> list[Finding]:
        findings: list[Finding] = []
        for tf in iter_text_fields(ctx.snapshot):
            if tf.kind in ("name", "uri", "property-name"):
                continue
            score, matches = instruction_matches(MatchView.of(tf.text))
            if score < THRESHOLD:
                continue
            hidden = any(carries_hidden_text(ev.text) for _, ev in matches)
            severity = Severity.HIGH if score >= HIGH_SCORE or hidden else Severity.MEDIUM
            labels = sorted({label for label, _ in matches})
            rationale = f"Instruction-like phrases (score {score}): {', '.join(labels)}."
            if hidden:
                rationale += " Some of them are hidden in invisible characters."
            findings.append(
                self.finding(
                    location=tf.location,
                    evidence=[ev for _, ev in matches],
                    rationale=rationale,
                    severity=severity,
                    confidence=Confidence.HIGH if score >= HIGH_SCORE else Confidence.MEDIUM,
                )
            )
        return findings

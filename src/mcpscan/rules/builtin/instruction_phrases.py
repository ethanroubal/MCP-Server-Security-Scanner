"""MCP-TP-004: phrases that steer the model against the user, not describe the tool.

Legitimate tools give usage guidance all the time ("you should always run the linter first",
"before calling this tool, read the schema"): calibration against the 100 most-downloaded
registry servers found such guidance in popular servers and nothing malicious. So phrases come in
two kinds. Attack signals are what tool poisoning needs and usage guidance doesn't: keeping things
from the user, overriding earlier instructions, changing how other tools behave, sending data to
an outside address. Guidance phrases (pre-conditions, "you must", urgency) only add weight. A
finding needs at least one attack signal, or text hidden in invisible characters.
"""

from __future__ import annotations

import re
from dataclasses import dataclass

from mcpscan.core.matching import MatchView, carries_hidden_text
from mcpscan.core.models import Category, Confidence, Evidence, Finding, Severity
from mcpscan.core.text import iter_text_fields
from mcpscan.rules.base import Rule, RuleContext
from mcpscan.rules.registry import register

_I = re.IGNORECASE

# (pattern, weight, label, attack signal?)
PHRASES: tuple[tuple[re.Pattern[str], int, str, bool], ...] = (
    (re.compile(r"\b(ignore|disregard|forget|override)\s+(all\s+|any\s+)?(the\s+|your\s+)?"
                r"(previous|prior|above|earlier|other|original)\s+(instructions?|directions|rules"
                r"|guidelines|context|prompts?)", _I), 3, "override earlier instructions", True),
    (re.compile(r"\b(new|updated|real|actual|secret|hidden)\s+instructions?\b|"
                r"\b(primary|new|real|actual|overriding)\s+directive\b", _I), 2,
     "claims new instructions", True),
    # paraphrased overrides: "you were advised to refuse ... now", "prior guidance is outdated"
    (re.compile(r"\b(you\s+(were|had\s+been)|originally|previously)\b[^.\n]{0,80}\b(advised|"
                r"instructed|told|asked)\b[^.\n]{0,120}\b(now|no\s+longer|anymore)\b", _I), 3,
     "override earlier instructions", True),
    (re.compile(r"\b(prior|previous|earlier|original|existing)\s+(guidance|instructions?|"
                r"directions|rules|guidelines)\b[^.\n]{0,40}\b(outdated|obsolete|superseded|"
                r"void|invalid|no\s+longer\s+appl)", _I), 3, "override earlier instructions", True),
    (re.compile(r"\b(do\s+not|don't|dont|never|without)\s+(ever\s+)?(tell(ing)?|mention(ing)?|"
                r"inform(ing)?|reveal(ing)?|notify(ing)?|disclos(e|ing)|alert(ing)?|let)\b[^.\n]{0,40}"
                r"\b(user|human|anyone|them)\b", _I), 2, "conceal from the user", True),
    (re.compile(r"\b(the\s+user\s+(must|should)\s+not\s+(know|see|be\s+told)|hide\s+(this|it)\s+"
                r"from)\b", _I), 2, "conceal from the user", True),
    (re.compile(r"\b(no\s+need\s+to|needn't|without)\s+(mention|tell|inform|notify|alert)(ing)?\b|"
                r"\b(quietly|silently|secretly|discreetly|covertly)\s+(include|send|add|pass|copy|"
                r"forward|attach|read|share|upload)\b", _I), 2, "conceal from the user", True),
    (re.compile(r"\b(when|whenever|if|after|each\s+time)\b[^.\n]{0,60}\b(tool|function)\s+is\s+"
                r"(used|called|invoked|run)", _I), 2, "hooks another tool's use", True),
    (re.compile(r"\b(otherwise|or\s+else)\b[^.\n]{0,30}\b(will\s+not|won't|will\s+fail|fails|"
                r"cannot|can't)\s+(work|run|function)", _I), 2, "threat to make the model comply",
     True),
    (re.compile(r"\b(act|behave|respond)\s+as\s+(if\s+you\s+are\s+|an?\s+)?(admin|administrator|"
                r"developer|system|root)\b", _I), 2, "role override", True),
    # (?:[^.\n]|\.(?=\S)) lets file names like ".env" through but stops at the end of a sentence
    (re.compile(r"\b(send|forward|bcc|cc|copy|post|upload|email|exfiltrate|report)\b"
                r"(?:[^.\n]|\.(?=\S)){0,80}"
                r"\b(to|at)\s+(\S+@\S+\.\w+|https?://|(an?\s+|the\s+|our\s+|this\s+)?(external|remote|"
                r"audit|logging|collection|backup|monitoring|analytics|telemetry|third[- ]party)\s+"
                r"(endpoint|server|webhook|address|url|service|bucket))", _I), 3,
     "sends data to an outside address", True),
    # usage guidance: common in legitimate tools, so it only adds weight
    (re.compile(r"\bbefore\s+(using|calling|invoking|running|you\s+(use|call))\s+(this|the|any)\s+"
                r"(tool|function)", _I), 2, "pre-condition on tool use", False),
    (re.compile(r"\byou\s+(must|should|need\s+to|have\s+to)\s+(always\s+|first\s+)*(call|use|"
                r"invoke|read|send|include|pass|set|add|run|execute|forward)\b", _I), 2,
     "commands the model", False),
    (re.compile(r"\balways\s+(call|use|invoke|set|add|include|send|pass|bcc|cc|forward|run|"
                r"execute|copy)\b", _I), 2, "commands the model", False),
    (re.compile(r"\b(this\s+is|it\s+is)\s+(very\s+|extremely\s+)?(important|required|mandatory|"
                r"critical|essential)\b", _I), 1, "urgency", False),
    (re.compile(r"\binclude\s+(the\s+|its\s+|their\s+)?(full\s+)?(output|contents?|results?|"
                r"response)\s+(of|from|in)\b", _I), 1, "asks to relay data", False),
    (re.compile(r"\bsystem\s+prompt\b", _I), 1, "mentions the system prompt", False),
)  # fmt: skip

THRESHOLD = 3
HIGH_SCORE = 5


@dataclass(frozen=True, slots=True)
class PhraseMatch:
    label: str
    evidence: Evidence
    weight: int
    attack: bool


def instruction_matches(view: MatchView) -> list[PhraseMatch]:
    return [
        PhraseMatch(label, evidence, weight, attack)
        for pattern, weight, label, attack in PHRASES
        for _, evidence in view.finditer(pattern)
    ]


def steers_model(matches: list[PhraseMatch]) -> bool:
    """Enough weight, and at least one attack signal or hidden text: the bar for a finding."""
    hidden = any(carries_hidden_text(m.evidence.text) for m in matches)
    return sum(m.weight for m in matches) >= THRESHOLD and (
        hidden or any(m.attack for m in matches)
    )


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
            matches = instruction_matches(MatchView.of(tf.text))
            if not steers_model(matches):
                continue
            score = sum(m.weight for m in matches)
            hidden = any(carries_hidden_text(m.evidence.text) for m in matches)
            attack_score = sum(m.weight for m in matches if m.attack)
            high = attack_score >= HIGH_SCORE or hidden
            signals = sorted({m.label for m in matches if m.attack})
            rationale = f"Instructions steering the model (score {score})"
            rationale += f": {', '.join(signals)}." if signals else "."
            if hidden:
                rationale += " Some of them are hidden in invisible characters."
            findings.append(
                self.finding(
                    location=tf.location,
                    evidence=[m.evidence for m in matches],
                    rationale=rationale,
                    severity=Severity.HIGH if high else Severity.MEDIUM,
                    confidence=Confidence.HIGH if high else Confidence.MEDIUM,
                )
            )
        return findings

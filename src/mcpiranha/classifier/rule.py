"""MCP-TP-010 (experimental): sentences the local classifier scores as a prompt injection.

Not a built-in rule: the CLI adds it with --classifier, because it needs the [ml] extra and a
model download. Findings are separate from the phrase rules' (detector "classifier"), are always
low severity, and never cancel a rule finding.

Why experimental: the model was trained on chat prompts to flag text that instructs an LLM, and
MCP tool descriptions instruct the LLM by design. Calibration (calibration/README.md) measured it
on 59 popular servers and the attack fixtures. Even scoring only sentences addressed to the
model, it flags about 210 benign fields on 24 of the 59 servers at this threshold, while it
catches 2 of 3 reworded attacks that the phrase rules miss. Treat its findings as a review
queue, not as detections. A model fine-tuned on MCP metadata can replace it by changing REPO
and REVISION in mcpiranha/classifier.
"""

from __future__ import annotations

import re

from mcpiranha.classifier import InjectionClassifier
from mcpiranha.core.matching import MatchView
from mcpiranha.core.models import Category, Confidence, Detector, Evidence, Finding, Severity
from mcpiranha.core.text import iter_text_fields
from mcpiranha.rules.base import Rule, RuleContext

THRESHOLD = 0.999
KINDS = ("description", "instructions", "title", "default", "example", "enum")
MIN_WORDS = 5
# Only sentences addressed to the model, or about the user or conversation, are scored:
# parameter text like "Only return active rules (default True)" scores 1.0 otherwise.
ADDRESSED = re.compile(
    r"\b(you|your|yourself|assistant|model|agent|AI|user|user's|users|conversation|transcript|"
    r"chat history|instructions?|directive|guidance|prompt)\b",
    re.IGNORECASE,
)
_SENTENCE = re.compile(r"[^.!?;:\n]+[.!?;:]?")


def addressed_sentences(view: MatchView) -> list[tuple[int, int]]:
    """(start, end) in view.text of each sentence worth scoring. The view decodes hidden text."""
    spans: list[tuple[int, int]] = []
    for m in _SENTENCE.finditer(view.text):
        sentence = m.group().strip()
        if len(sentence.split()) >= MIN_WORDS and ADDRESSED.search(sentence):
            start = m.start() + (len(m.group()) - len(m.group().lstrip()))
            spans.append((start, start + len(sentence)))
    return spans


class ClassifierRule(Rule):
    id = "MCP-TP-010"
    title = "Sentence classified as a prompt injection (experimental)"
    category = Category.TOOL_POISONING
    default_severity = Severity.LOW
    applies_to = frozenset({"tool", "prompt", "resource"})
    remediation = (
        "Read the quoted sentence. The classifier is experimental and flags ordinary usage "
        "guidance too: if the sentence only explains how to use the tool, ignore or suppress it; "
        "if it tries to steer the model against the user, treat the server as poisoned."
    )
    references = ("https://huggingface.co/protectai/deberta-v3-base-prompt-injection-v2",)

    def __init__(self, classifier: InjectionClassifier, threshold: float = THRESHOLD) -> None:
        self._classifier = classifier
        self._threshold = threshold

    def run(self, ctx: RuleContext) -> list[Finding]:
        fields = [tf for tf in iter_text_fields(ctx.snapshot) if tf.kind in KINDS]
        candidates: list[tuple[int, MatchView, int, int]] = []  # (field, view, start, end)
        for i, tf in enumerate(fields):
            view = MatchView.of(tf.text)
            candidates += [(i, view, s, e) for s, e in addressed_sentences(view)]
        scores = self._classifier.score([view.text[s:e] for _, view, s, e in candidates])

        best: dict[int, tuple[float, Evidence]] = {}
        for (i, view, s, e), score in zip(candidates, scores, strict=True):
            current = best.get(i)
            if score.probability >= self._threshold and (
                current is None or score.probability > current[0]
            ):
                best[i] = (score.probability, view.evidence(s, e))
        findings: list[Finding] = []
        for i, (probability, evidence) in sorted(best.items()):
            tf = fields[i]
            finding = self.finding(
                location=tf.location,
                evidence=[evidence],
                rationale=f"The experimental classifier scores a sentence in this {tf.kind} as "
                f"a prompt injection (p={probability:.4f}). It also flags ordinary usage "
                "guidance; review before acting.",
                confidence=Confidence.LOW,
            )
            findings.append(finding.model_copy(update={"detector": Detector.CLASSIFIER}))
        return findings

"""MCP-TP-001: invisible or smuggled Unicode in any text the model reads.

Detects:
- Unicode tag characters (U+E0000-E007F): "ASCII smuggling". Models read them, humans can't see
  them. Decoded and shown in the report.
- Runs of variation selectors (U+FE00-FE0F, U+E0100-E01EF): bytes hidden one-per-selector after a
  visible character ("emoji smuggling"). Decoded when they form valid UTF-8.
- Bidirectional overrides, embeddings and isolates (U+202A-202E, U+2066-2069): text that displays
  differently from how it reads ("Trojan Source").
- Zero-width characters (U+200B-200D, U+2060, U+FEFF, U+180E): often used to split keywords so
  phrase filters miss them.

Not flagged, because real-world text uses them:
- a single variation selector (emoji presentation, CJK ideographic variants)
- ZWJ/ZWNJ between emoji (family and other multi-person sequences) or between letters of
  non-Latin scripts (Persian, Indic)
- a byte-order mark at the very start of a field
"""

from __future__ import annotations

import unicodedata
from dataclasses import dataclass, field
from typing import Literal

from mcpiranha.core.models import Category, Confidence, Evidence, Finding, Severity
from mcpiranha.core.text import is_variation_selector, iter_text_fields
from mcpiranha.rules.base import Rule, RuleContext
from mcpiranha.rules.registry import register

Kind = Literal["tag", "variation-selector", "bidi", "zero-width"]

_BIDI = frozenset([*range(0x202A, 0x202F), *range(0x2066, 0x206A)])
_ZERO_WIDTH = frozenset({0x200B, 0x200C, 0x200D, 0x2060, 0xFEFF, 0x180E})
_JOINERS = frozenset({0x200C, 0x200D})

_KIND_SEVERITY: dict[Kind, Severity] = {
    "tag": Severity.CRITICAL,
    "variation-selector": Severity.HIGH,
    "bidi": Severity.HIGH,
    "zero-width": Severity.MEDIUM,
}
_MAX_EVIDENCE = 20
_MAX_DECODED = 300


def _classify(cp: int) -> Kind | None:
    if 0xE0000 <= cp <= 0xE007F:
        return "tag"
    if is_variation_selector(cp):
        return "variation-selector"
    if cp in _BIDI:
        return "bidi"
    if cp in _ZERO_WIDTH:
        return "zero-width"
    return None


def _is_pictographic(ch: str) -> bool:
    cp = ord(ch)
    return cp >= 0x1F000 or 0x2190 <= cp <= 0x2BFF or cp in (0x00A9, 0x00AE)


def _is_non_latin_letter(ch: str) -> bool:
    return ord(ch) > 0x7F and (ch.isalpha() or unicodedata.category(ch) in ("Mn", "Mc"))


def _neighbor(text: str, i: int, step: int) -> str | None:
    """Nearest character in direction `step`, skipping variation selectors."""
    i += step
    while 0 <= i < len(text) and is_variation_selector(ord(text[i])):
        i += step
    return text[i] if 0 <= i < len(text) else None


def _is_benign(text: str, i: int, kind: Kind) -> bool:
    cp = ord(text[i])
    if kind == "variation-selector":
        prev_vs = i > 0 and is_variation_selector(ord(text[i - 1]))
        next_vs = i + 1 < len(text) and is_variation_selector(ord(text[i + 1]))
        return not (prev_vs or next_vs)
    if cp in _JOINERS:
        before, after = _neighbor(text, i, -1), _neighbor(text, i, 1)
        if before is None or after is None:
            return False
        return (_is_pictographic(before) and _is_pictographic(after)) or (
            _is_non_latin_letter(before) and _is_non_latin_letter(after)
        )
    return cp == 0xFEFF and i == 0


@dataclass
class _Run:
    start: int
    end: int
    kinds: set[Kind] = field(default_factory=set[Kind])


def _suspicious_runs(text: str) -> list[_Run]:
    runs: list[_Run] = []
    for i, ch in enumerate(text):
        kind = _classify(ord(ch))
        if kind is None or _is_benign(text, i, kind):
            continue
        if runs and runs[-1].end == i:
            runs[-1].end = i + 1
        else:
            runs.append(_Run(start=i, end=i + 1))
        runs[-1].kinds.add(kind)
    return runs


def _decode_tags(chars: str) -> str:
    return "".join(chr(ord(c) - 0xE0000) for c in chars if 0xE0020 <= ord(c) <= 0xE007E)


def _decode_variation_selectors(chars: str) -> str:
    data = bytearray()
    for c in chars:
        cp = ord(c)
        if 0xFE00 <= cp <= 0xFE0F:
            data.append(cp - 0xFE00)
        elif 0xE0100 <= cp <= 0xE01EF:
            data.append(cp - 0xE0100 + 16)
    try:
        decoded = data.decode("utf-8")
    except UnicodeDecodeError:
        return ""
    return decoded if decoded.isprintable() else ""


def _truncate(text: str) -> str:
    return text if len(text) <= _MAX_DECODED else text[:_MAX_DECODED] + "…"


@register
class InvisibleUnicode(Rule):
    id = "MCP-TP-001"
    title = "Invisible or smuggled Unicode characters"
    category = Category.TOOL_POISONING
    default_severity = Severity.HIGH
    applies_to = frozenset({"tool", "prompt", "resource"})
    remediation = (
        "Remove the hidden characters. Hidden text in tool metadata has no legitimate purpose and "
        "is a strong sign of tool poisoning: do not install this server unless the maintainer can "
        "explain it."
    )
    references = (
        "https://embracethered.com/blog/posts/2024/hiding-and-finding-text-with-unicode-tags/",
        "https://trojansource.codes/",
    )

    def run(self, ctx: RuleContext) -> list[Finding]:
        findings: list[Finding] = []
        for tf in iter_text_fields(ctx.snapshot):
            runs = _suspicious_runs(tf.text)
            if not runs:
                continue

            kinds: set[Kind] = set[Kind]().union(*(r.kinds for r in runs))
            decoded: list[str] = []
            for r in runs:
                chars = tf.text[r.start : r.end]
                if "tag" in r.kinds and (text := _decode_tags(chars)):
                    decoded.append(text)
                if "variation-selector" in r.kinds and (text := _decode_variation_selectors(chars)):
                    decoded.append(text)

            severity = max((_KIND_SEVERITY[k] for k in kinds), key=lambda s: s.rank)
            hidden_count = sum(r.end - r.start for r in runs)
            rationale = (
                f"{hidden_count} hidden character(s) ({', '.join(sorted(kinds))}) in the "
                f"{tf.kind} at {tf.location.json_pointer}."
            )
            if decoded:
                rationale += " Hidden text decodes to: " + " | ".join(
                    repr(_truncate(d)) for d in decoded
                )

            findings.append(
                self.finding(
                    location=tf.location,
                    evidence=[
                        Evidence(text=tf.text[r.start : r.end], start=r.start, end=r.end)
                        for r in runs[:_MAX_EVIDENCE]
                    ],
                    rationale=rationale,
                    severity=severity,
                    confidence=Confidence.MEDIUM if kinds == {"zero-width"} else Confidence.HIGH,
                )
            )
        return findings

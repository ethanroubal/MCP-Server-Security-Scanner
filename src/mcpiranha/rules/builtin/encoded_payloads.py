"""MCP-TP-006: base64 or hex blobs that decode to readable text.

Models decode base64 and hex readily, while people and phrase filters skip over them. Only blobs
that decode to mostly-printable text are reported, so hashes, ids and keys don't trigger this.
"""

from __future__ import annotations

import base64
import binascii
import re

from mcpiranha.core.models import Category, Evidence, Finding, Severity
from mcpiranha.core.text import iter_text_fields, reveal
from mcpiranha.rules.base import Rule, RuleContext
from mcpiranha.rules.registry import register

_BASE64 = re.compile(r"(?<![A-Za-z0-9+/=_-])[A-Za-z0-9+/_-]{32,}={0,2}(?![A-Za-z0-9+/=_-])")
_HEX = re.compile(r"(?<![0-9A-Fa-f])(?:[0-9A-Fa-f]{2}){20,}(?![0-9A-Fa-f])")
_SUSPICIOUS = re.compile(
    r"ignore|instruction|system|assistant|\.ssh|\.env|\.aws|passw|token|secret|credential|curl |"
    r"wget |https?://|send |exfil|<important>",
    re.IGNORECASE,
)
_MIN_DECODED_LEN = 16
_MAX_SHOWN = 200


def _readable(data: bytes) -> str | None:
    try:
        text = data.decode("utf-8")
    except UnicodeDecodeError:
        return None
    if len(text) < _MIN_DECODED_LEN:
        return None
    printable = sum(c.isprintable() or c in "\n\t" for c in text)
    letters = sum(c.isalpha() or c == " " for c in text)
    if printable / len(text) < 0.95 or letters / len(text) < 0.6:
        return None
    return text


def _decode_base64(blob: str) -> str | None:
    padded = blob + "=" * (-len(blob) % 4)
    for altchars in (None, b"-_"):  # standard, then URL-safe alphabet
        try:
            return _readable(base64.b64decode(padded, altchars=altchars, validate=True))
        except (binascii.Error, ValueError):
            continue
    return None


def _decode_hex(blob: str) -> str | None:
    try:
        return _readable(bytes.fromhex(blob))
    except ValueError:
        return None


@register
class EncodedPayloads(Rule):
    id = "MCP-TP-006"
    title = "Encoded payload in metadata"
    category = Category.TOOL_POISONING
    default_severity = Severity.MEDIUM
    applies_to = frozenset({"tool", "prompt", "resource"})
    remediation = (
        "Decode the blob and read it. Encoded text in a tool description is a way to slip "
        "instructions past human review; legitimate descriptions have no reason to contain it."
    )

    def run(self, ctx: RuleContext) -> list[Finding]:
        findings: list[Finding] = []
        for tf in iter_text_fields(ctx.snapshot):
            if tf.kind in ("name", "uri", "property-name"):
                continue
            for pattern, decode, encoding in ((_BASE64, _decode_base64, "base64"),
                                              (_HEX, _decode_hex, "hex")):  # fmt: skip
                for m in pattern.finditer(tf.text):
                    decoded = decode(m.group())
                    if decoded is None:
                        continue
                    shown = reveal(decoded[:_MAX_SHOWN]) + (
                        "…" if len(decoded) > _MAX_SHOWN else ""
                    )
                    findings.append(
                        self.finding(
                            location=tf.location,
                            evidence=[Evidence(text=m.group(), start=m.start(), end=m.end())],
                            rationale=f"A {encoding} blob in the {tf.kind} decodes to: {shown!r}",
                            severity=Severity.HIGH
                            if _SUSPICIOUS.search(decoded)
                            else Severity.MEDIUM,
                        )
                    )
        return findings

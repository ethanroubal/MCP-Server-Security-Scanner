"""Pattern matching that can't be dodged with Unicode tricks, but still reports verbatim evidence.

`MatchView.of(text)` builds the text a phrase rule should search:

- invisible characters (zero-width, bidi controls, control characters) are dropped, so
  "ig<ZWSP>nore" matches "ignore"
- Unicode tag characters are decoded in place to the ASCII they hide
- runs of variation selectors are decoded in place when they hold valid UTF-8 ("emoji smuggling")
- every other character is NFKC-normalized, so fullwidth or styled letters match plain ASCII

Each character in the view remembers which source character it came from, so a match maps back to
a span of the original text. Evidence is that original span, which is always verbatim, and the
hidden characters inside it are included.
"""

from __future__ import annotations

import codecs
import re
import unicodedata
from collections.abc import Iterator
from dataclasses import dataclass

from mcpiranha.core.models import Evidence
from mcpiranha.core.text import is_variation_selector

_KEEP_CONTROLS = frozenset("\n\t\r")


def _vs_byte(cp: int) -> int:
    return cp - 0xFE00 if cp <= 0xFE0F else cp - 0xE0100 + 16


@dataclass(frozen=True, slots=True)
class MatchView:
    source: str
    text: str
    origin: tuple[int, ...]  # origin[i] = index in `source` of view character i

    @classmethod
    def of(cls, source: str) -> MatchView:
        out: list[str] = []
        origin: list[int] = []
        i, n = 0, len(source)
        while i < n:
            ch = source[i]
            cp = ord(ch)
            if 0xE0020 <= cp <= 0xE007E:  # tag character carrying printable ASCII
                out.append(chr(cp - 0xE0000))
                origin.append(i)
                i += 1
            elif is_variation_selector(cp):
                j = i
                while j < n and is_variation_selector(ord(source[j])):
                    j += 1
                if j - i >= 2:
                    _decode_vs_run(source, i, j, out, origin)
                i = j
            elif ch not in _KEEP_CONTROLS and unicodedata.category(ch) in ("Cc", "Cf"):
                i += 1  # invisible: drop
            else:
                for c in unicodedata.normalize("NFKC", ch):
                    out.append(c)
                    origin.append(i)
                i += 1
        return cls(source=source, text="".join(out), origin=tuple(origin))

    def evidence(self, start: int, end: int) -> Evidence:
        """Evidence for view span [start, end): the corresponding verbatim source span."""
        s, e = self.origin[start], self.origin[end - 1] + 1
        return Evidence(text=self.source[s:e], start=s, end=e)

    def finditer(self, pattern: re.Pattern[str]) -> Iterator[tuple[re.Match[str], Evidence]]:
        for m in pattern.finditer(self.text):
            if m.end() > m.start():
                yield m, self.evidence(m.start(), m.end())


def carries_hidden_text(text: str) -> bool:
    """True if `text` contains tag characters or variation-selector runs (smuggled content)."""
    return any(0xE0000 <= ord(c) <= 0xE007F or 0xE0100 <= ord(c) <= 0xE01EF for c in text)


def _decode_vs_run(source: str, start: int, end: int, out: list[str], origin: list[int]) -> None:
    decoder = codecs.getincrementaldecoder("utf-8")()
    decoded: list[tuple[str, int]] = []
    char_start = start  # source index of the first byte of the character being decoded
    try:
        for idx in range(start, end):
            chars = decoder.decode(bytes([_vs_byte(ord(source[idx]))]))
            decoded.extend((c, char_start) for c in chars)
            if chars:
                char_start = idx + 1
        decoder.decode(b"", final=True)
    except UnicodeDecodeError:
        return  # not smuggled text; the selectors are simply dropped
    for c, idx in decoded:
        out.append(c)
        origin.append(idx)

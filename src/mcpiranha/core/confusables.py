"""Look-alike characters, for comparing names the way a model or a person would read them.

A small, hand-picked subset of Unicode's confusables data: Cyrillic and Greek letters that render
like Latin ones. Written as code points so the source itself contains no look-alikes.
"""

from __future__ import annotations

import unicodedata

_LATIN_LOOKALIKES: dict[int, str] = {
    # Cyrillic lowercase
    0x0430: "a", 0x0432: "b", 0x0435: "e", 0x043A: "k", 0x043C: "m", 0x043D: "h", 0x043E: "o",
    0x0440: "p", 0x0441: "c", 0x0442: "t", 0x0443: "y", 0x0445: "x", 0x0455: "s", 0x0456: "i",
    0x0458: "j", 0x0501: "d", 0x051B: "q", 0x051D: "w", 0x04BB: "h", 0x0261: "g",
    # Cyrillic uppercase
    0x0410: "a", 0x0412: "b", 0x0415: "e", 0x041A: "k", 0x041C: "m", 0x041D: "h", 0x041E: "o",
    0x0420: "p", 0x0421: "c", 0x0422: "t", 0x0425: "x", 0x0405: "s", 0x0406: "i", 0x0408: "j",
    # Greek
    0x03B1: "a", 0x03B5: "e", 0x03B9: "i", 0x03BA: "k", 0x03BD: "v", 0x03BF: "o", 0x03C1: "p",
    0x03C4: "t", 0x03C5: "u", 0x03C7: "x", 0x0391: "a", 0x0392: "b", 0x0395: "e", 0x0396: "z",
    0x0397: "h", 0x0399: "i", 0x039A: "k", 0x039C: "m", 0x039D: "n", 0x039F: "o", 0x03A1: "p",
    0x03A4: "t", 0x03A5: "y", 0x03A7: "x",
    # Latin look-alikes outside ASCII
    0x0131: "i", 0x0269: "i", 0x01C0: "l", 0x2113: "l",
}  # fmt: skip

_SEPARATORS = str.maketrans({"-": "_", " ": "_", ".": "_"})


def skeleton(name: str) -> str:
    """Comparison key: NFKC, invisibles removed, look-alikes mapped to Latin, case and
    separators folded. Two names with the same skeleton read the same to a model or a person."""
    out: list[str] = []
    for ch in unicodedata.normalize("NFKC", name):
        if unicodedata.category(ch) in ("Cf", "Cc", "Mn"):
            continue
        out.append(_LATIN_LOOKALIKES.get(ord(ch), ch))
    return "".join(out).casefold().translate(_SEPARATORS)


def edit_distance(a: str, b: str, limit: int = 3) -> int:
    """Optimal-string-alignment distance (adjacent swaps count as one), capped at `limit`."""
    if abs(len(a) - len(b)) >= limit:
        return limit
    prev2: list[int] = []
    prev = list(range(len(b) + 1))
    for i, ca in enumerate(a, 1):
        cur = [i, *([0] * len(b))]
        for j, cb in enumerate(b, 1):
            cost = ca != cb
            cur[j] = min(prev[j] + 1, cur[j - 1] + 1, prev[j - 1] + cost)
            if i > 1 and j > 1 and ca == b[j - 2] and a[i - 2] == cb:
                cur[j] = min(cur[j], prev2[j - 2] + 1)
        if min(cur) >= limit:
            return limit
        prev2, prev = prev, cur
    return min(prev[-1], limit)

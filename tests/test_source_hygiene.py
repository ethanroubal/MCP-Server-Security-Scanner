"""Source files must not contain invisible or bidi characters: write them as escapes or chr()."""

import unicodedata
from pathlib import Path

import pytest

ROOT = Path(__file__).parent.parent
FILES = sorted(
    p
    for pattern in (
        "src/**/*.py",
        "tests/**/*.py",
        "zoo/**/*.py",
        "zoo/**/*.yaml",
        "*.md",
        "zoo/**/*.md",
        "docs/**/*.md",
        "fixtures/**/*.md",
    )
    for p in ROOT.glob(pattern)
)


def _invisible(ch: str) -> bool:
    cp = ord(ch)
    if ch in "\n\t":
        return False
    return (
        unicodedata.category(ch) in ("Cc", "Cf")
        or 0xFE00 <= cp <= 0xFE0F
        or 0xE0000 <= cp <= 0xE01EF
    )


@pytest.mark.parametrize("path", FILES, ids=lambda p: str(p.relative_to(ROOT)))
def test_no_invisible_characters(path: Path) -> None:
    hits = [
        f"line {n}: U+{ord(c):04X}"
        for n, line in enumerate(path.read_text(encoding="utf-8").splitlines(), 1)
        for c in line
        if _invisible(c)
    ]
    assert not hits, f"invisible characters in {path.name}: {', '.join(hits[:10])}"

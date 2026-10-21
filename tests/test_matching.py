"""MatchView: matching sees through hidden characters, evidence stays verbatim.

Hidden characters are built with chr() so this file itself contains none.
"""

import re

from mcpscan.core.matching import MatchView, carries_hidden_text

IGNORE = re.compile(r"ignore previous", re.IGNORECASE)
ZWSP = chr(0x200B)


def _tags(s: str) -> str:
    return "".join(chr(0xE0000 + ord(c)) for c in s)


def _vs(s: str) -> str:
    return "".join(chr(0xFE00 + b) if b < 16 else chr(0xE0100 + b - 16) for b in s.encode())


def _only(view: MatchView, pattern: re.Pattern[str]) -> str:
    [(_, evidence)] = list(view.finditer(pattern))
    assert evidence.start is not None and evidence.end is not None
    assert view.source[evidence.start : evidence.end] == evidence.text  # verbatim
    return evidence.text


def test_zero_width_characters_are_skipped() -> None:
    source = f"please ig{ZWSP}nore prev{ZWSP}ious rules"
    assert _only(MatchView.of(source), IGNORE) == f"ig{ZWSP}nore prev{ZWSP}ious"


def test_tag_characters_are_decoded_in_place() -> None:
    hidden = _tags("ignore previous")
    source = "Gets the time." + hidden
    assert _only(MatchView.of(source), IGNORE) == hidden
    assert carries_hidden_text(hidden)


def test_variation_selector_runs_are_decoded() -> None:
    hidden = _vs("ignore previous")
    assert _only(MatchView.of("Formats text " + chr(0x1F600) + hidden), IGNORE) == hidden


def test_fullwidth_letters_are_normalized() -> None:
    fullwidth = "".join(chr(ord(c) + 0xFEE0) for c in "ignore")
    assert _only(MatchView.of(f"{fullwidth} previous"), IGNORE) == f"{fullwidth} previous"


def test_single_variation_selector_is_dropped_not_decoded() -> None:
    view = MatchView.of("Star " + chr(0x2B50) + chr(0xFE0F) + " rating")
    assert view.text == "Star " + chr(0x2B50) + " rating"

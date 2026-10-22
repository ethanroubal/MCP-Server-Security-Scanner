import pytest

from mcpiranha.core.models import Confidence
from mcpiranha.core.secrets import classify, redact_args

GITHUB = "ghp_" + "A1b2C3d4" * 5  # fake


@pytest.mark.parametrize(
    ("name", "value", "label", "confidence"),
    [
        ("GITHUB_TOKEN", GITHUB, "GitHub token", Confidence.HIGH),
        ("anything", GITHUB, "GitHub token", Confidence.HIGH),  # known format wins over the name
        ("Authorization", "Bearer abcdefghijklmnopqrstuvwxyz", "bearer token", Confidence.HIGH),
        ("MY_API_KEY", "q8Zr2LmX9vTp4KwN7sYb", "secret-looking value", Confidence.MEDIUM),
    ],
)
def test_detects_secrets(name: str, value: str, label: str, confidence: Confidence) -> None:
    hit = classify(name, value)
    assert hit is not None
    assert (hit[0], hit[2]) == (label, confidence)


@pytest.mark.parametrize(
    ("name", "value"),
    [
        ("GITHUB_TOKEN", "${GITHUB_TOKEN}"),
        ("API_KEY", "${env:API_KEY}"),
        ("Authorization", "Bearer ${input:token}"),
        ("API_KEY", "your-api-key-here"),
        ("PASSWORD", "changeme"),
        ("SECRET", "op://vault/item/field"),
        ("DEBUG", "true"),
        ("API_KEY", "aaaaaaaaaaaa"),  # low entropy
        ("LOG_LEVEL", "q8Zr2LmX9vTp4KwN7sYb"),  # random, but not a secret-looking name
    ],
)
def test_ignores_placeholders_and_non_secrets(name: str, value: str) -> None:
    assert classify(name, value) is None


def test_redact_args() -> None:
    redacted = redact_args(["-y", "pkg", f"--token={GITHUB}", "--api-key", "q8Zr2LmX9vTp4KwN7sYb"])
    assert redacted[:2] == ["-y", "pkg"]
    assert redacted[2].startswith("--token=<redacted sha256:")
    assert redacted[3] == "--api-key"
    assert redacted[4].startswith("<redacted sha256:")
    assert GITHUB not in "".join(redacted)

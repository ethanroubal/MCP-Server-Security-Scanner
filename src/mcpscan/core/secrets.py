"""Recognize secrets in launch configuration, and redact them.

Shared by MCP-CF-001 (which reports plaintext secrets) and the lockfile (which must never write
one to disk, since lockfiles get committed).
"""

from __future__ import annotations

import math
import re
from collections import Counter
from collections.abc import Iterator
from urllib.parse import parse_qsl, urlsplit

from mcpscan.core.hashing import sha256_hex
from mcpscan.core.models import Confidence, Launch
from mcpscan.core.text import pointer_token

# (label, pattern, length of the non-secret prefix that may be shown)
KNOWN_TOKENS: tuple[tuple[str, re.Pattern[str], int], ...] = (
    ("GitHub token", re.compile(r"\bgh[pousr]_[A-Za-z0-9]{36,}"), 4),
    ("GitHub fine-grained token", re.compile(r"\bgithub_pat_[A-Za-z0-9_]{50,}"), 11),
    ("Anthropic API key", re.compile(r"\bsk-ant-[A-Za-z0-9_-]{20,}"), 7),
    ("OpenAI API key", re.compile(r"\bsk-(?:proj-|svcacct-|admin-)?[A-Za-z0-9_-]{20,}"), 3),
    ("Slack token", re.compile(r"\bxox[abposr]-[A-Za-z0-9-]{10,}"), 5),
    ("AWS access key id", re.compile(r"\b(?:AKIA|ASIA)[0-9A-Z]{16}\b"), 4),
    ("Google API key", re.compile(r"\bAIza[0-9A-Za-z_-]{35}"), 4),
    ("GitLab token", re.compile(r"\bglpat-[A-Za-z0-9_-]{20,}"), 6),
    ("Stripe key", re.compile(r"\b[sr]k_(?:live|test)_[A-Za-z0-9]{16,}"), 8),
    ("npm token", re.compile(r"\bnpm_[A-Za-z0-9]{36}\b"), 4),
    ("Hugging Face token", re.compile(r"\bhf_[A-Za-z0-9]{30,}"), 3),
    ("Notion token", re.compile(r"\b(?:secret_|ntn_)[A-Za-z0-9]{40,}"), 4),
    ("Linear API key", re.compile(r"\blin_api_[A-Za-z0-9]{30,}"), 8),
    ("private key", re.compile(r"-----BEGIN [A-Z ]*PRIVATE KEY-----"), 0),
    ("JWT", re.compile(r"\beyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}"), 3),
)

SECRET_NAME = re.compile(
    r"(token|secret|passw(or)?d|passwd|pwd|api[_-]?key|apikey|access[_-]?key|private[_-]?key|"
    r"credential|auth|session|cookie|bearer|client[_-]?secret|signing[_-]?key)",
    re.IGNORECASE,
)
_PLACEHOLDER = re.compile(
    r"^\$\{?[A-Za-z_][\w:.-]*\}?$|\$\{|\{(?:env|file):|^%[A-Za-z_]\w*%$|"
    r"^(op|vault|keychain|secret|aws-sm)://|"
    r"^<.*>$|your[_-]|xxx|changeme|placeholder|example|dummy|redacted|\*{4}|^replace|^todo$|^none$|^null$",
    re.IGNORECASE,
)
_FLAG_WITH_VALUE = re.compile(r"^(--?[A-Za-z][\w-]*)=(.+)$")
_MIN_GENERIC_LEN = 8
_MIN_ENTROPY = 3.0


def _entropy(value: str) -> float:
    counts = Counter(value)
    return -sum(n / len(value) * math.log2(n / len(value)) for n in counts.values())


def classify(name: str, value: str) -> tuple[str, int, Confidence] | None:
    """(description, shown prefix length, confidence) if `value` looks like a real secret."""
    value = value.strip()
    if not value or _PLACEHOLDER.search(value):
        return None
    for label, pattern, prefix in KNOWN_TOKENS:
        if pattern.search(value):
            return label, prefix, Confidence.HIGH
    if value.lower().startswith("bearer ") and len(value) > 20:
        return "bearer token", 7, Confidence.HIGH
    if (
        SECRET_NAME.search(name)
        and len(value) >= _MIN_GENERIC_LEN
        and " " not in value
        and _entropy(value) >= _MIN_ENTROPY
    ):
        return "secret-looking value", 0, Confidence.MEDIUM
    return None


def secret_candidates(launch: Launch) -> Iterator[tuple[str, str, str]]:
    """(name shown as evidence, value, JSON pointer) for every place a secret could sit."""
    for key, secret in launch.env.items():
        yield key, secret.get_secret_value(), f"/launch/env/{pointer_token(key)}"
    for key, secret in launch.headers.items():
        yield key, secret.get_secret_value(), f"/launch/headers/{pointer_token(key)}"
    for i, arg in enumerate(launch.args):
        if m := _FLAG_WITH_VALUE.match(arg):
            yield m.group(1), m.group(2), f"/launch/args/{i}"
        elif (
            i > 0 and launch.args[i - 1].startswith("-") and SECRET_NAME.search(launch.args[i - 1])
        ):
            yield launch.args[i - 1], arg, f"/launch/args/{i}"
        else:
            yield f"argument {i}", arg, f"/launch/args/{i}"
    if launch.url:
        parts = urlsplit(launch.url)
        if parts.password:
            yield "URL credentials", parts.password, "/launch/url"
        for key, value in parse_qsl(parts.query):
            yield key, value, "/launch/url"


def redacted(value: str) -> str:
    """A stand-in that still changes whenever the secret does."""
    return f"<redacted sha256:{sha256_hex(value)[:12]}>"


def redact_args(args: list[str]) -> list[str]:
    """`args` with every secret-looking value replaced by `redacted()`."""
    out: list[str] = []
    for i, arg in enumerate(args):
        if (m := _FLAG_WITH_VALUE.match(arg)) and classify(m.group(1), m.group(2)):
            out.append(f"{m.group(1)}={redacted(m.group(2))}")
            continue
        flag = args[i - 1] if i > 0 and args[i - 1].startswith("-") else f"argument {i}"
        out.append(redacted(arg) if classify(flag, arg) else arg)
    return out


def mask_secrets(text: str) -> str:
    """`text` with every known token format replaced, for showing server output safely."""
    for _, pattern, _ in KNOWN_TOKENS:
        text = pattern.sub("<redacted>", text)
    return text

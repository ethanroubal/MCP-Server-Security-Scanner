"""Canonical JSON hashing, used for finding ids and lockfile pins."""

import hashlib
import json
from typing import Any


def canonical_json(value: Any) -> str:
    """Serialize deterministically: sorted keys, no whitespace, Unicode kept as-is."""
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=False)


def sha256_hex(text: str) -> str:
    return hashlib.sha256(text.encode("utf-8")).hexdigest()


def hash_json(value: Any) -> str:
    return sha256_hex(canonical_json(value))

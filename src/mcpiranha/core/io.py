"""Loading snapshots from disk."""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any, cast

from pydantic import TypeAdapter

from mcpiranha.core.models import ServerSnapshot

_SNAPSHOTS = TypeAdapter(list[ServerSnapshot])


def looks_like_snapshots(data: Any) -> bool:
    """True for one ServerSnapshot object or a list of them (as opposed to a client config)."""
    items: list[Any] = cast(list[Any], data) if isinstance(data, list) else [data]
    return all(isinstance(i, dict) and "origin" in i and "id" in i for i in items)


def parse_snapshots(data: Any) -> list[ServerSnapshot]:
    return _SNAPSHOTS.validate_python([data] if isinstance(data, dict) else data)


def load_snapshots(path: Path) -> list[ServerSnapshot]:
    """Read a snapshot file holding one `ServerSnapshot` object or a list of them (an inventory)."""
    return parse_snapshots(json.loads(path.read_text(encoding="utf-8")))

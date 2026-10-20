"""Loading snapshots from disk."""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

from pydantic import TypeAdapter

from mcpscan.core.models import ServerSnapshot

_SNAPSHOTS = TypeAdapter(list[ServerSnapshot])


def load_snapshots(path: Path) -> list[ServerSnapshot]:
    """Read a snapshot file holding one `ServerSnapshot` object or a list of them (an inventory)."""
    data: Any = json.loads(path.read_text(encoding="utf-8"))
    if isinstance(data, dict):
        data = [data]
    return _SNAPSHOTS.validate_python(data)

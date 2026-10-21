"""JSON with comments and trailing commas, as VS Code writes its settings and mcp.json files."""

from __future__ import annotations

import json
from typing import Any

_BOM = chr(0xFEFF)


def strip_jsonc(text: str) -> str:
    """Remove // and /* */ comments and trailing commas, leaving strings untouched."""
    out: list[str] = []
    i, n = 0, len(text)
    in_string = False
    while i < n:
        ch = text[i]
        if in_string:
            out.append(ch)
            if ch == "\\" and i + 1 < n:
                out.append(text[i + 1])
                i += 1
            elif ch == '"':
                in_string = False
        elif ch == '"':
            in_string = True
            out.append(ch)
        elif text.startswith("//", i):
            while i < n and text[i] != "\n":
                i += 1
            continue
        elif text.startswith("/*", i):
            end = text.find("*/", i + 2)
            i = n if end < 0 else end + 2
            continue
        elif ch in "}]":
            # drop a trailing comma before this closer (ignoring whitespace already emitted)
            j = len(out) - 1
            while j >= 0 and out[j].isspace():
                j -= 1
            if j >= 0 and out[j] == ",":
                del out[j]
            out.append(ch)
        else:
            out.append(ch)
        i += 1
    return "".join(out)


def loads(text: str) -> Any:
    return json.loads(strip_jsonc(text.removeprefix(_BOM)))

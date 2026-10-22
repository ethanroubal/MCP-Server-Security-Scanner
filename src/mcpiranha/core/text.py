"""Walk every piece of text in a snapshot that a model will read, and render it safely for humans.

Attackers hide payloads where people don't look: nested schema property descriptions, enum values,
defaults, prompt arguments. Rules should iterate `iter_text_fields` rather than reading
`tool.description` directly, so they cover all of it.
"""

from __future__ import annotations

import unicodedata
from collections.abc import Iterator
from dataclasses import dataclass
from typing import Any, Literal, cast

from mcpiranha.core.models import Location, ServerSnapshot

FieldKind = Literal[
    "name", "title", "description", "instructions", "uri", "property-name", "enum", "default",
    "const", "example",
]  # fmt: skip

# Schema keys whose string values are shown to the model.
_SCHEMA_TEXT_KEYS: dict[str, FieldKind] = {
    "description": "description",
    "title": "title",
    "default": "default",
    "const": "const",
}
_SCHEMA_LIST_KEYS: dict[str, FieldKind] = {"enum": "enum", "examples": "example"}

_ITEM_KEYS: tuple[tuple[str, FieldKind], ...] = (
    ("name", "name"),
    ("title", "title"),
    ("description", "description"),
)


@dataclass(frozen=True, slots=True)
class TextField:
    location: Location
    kind: FieldKind
    text: str


def pointer_token(token: str | int) -> str:
    """Escape one RFC 6901 JSON pointer reference token."""
    return str(token).replace("~", "~0").replace("/", "~1")


def _at(loc: Location, pointer: str) -> Location:
    return loc.model_copy(update={"json_pointer": pointer})


def _fields(item: object, keys: tuple[tuple[str, FieldKind], ...], loc: Location, base: str
            ) -> Iterator[TextField]:  # fmt: skip
    for key, kind in keys:
        text = getattr(item, key)
        if isinstance(text, str) and text:
            yield TextField(_at(loc, f"{base}/{key}"), kind, text)


def iter_text_fields(snapshot: ServerSnapshot) -> Iterator[TextField]:
    server = Location(server_id=snapshot.id)

    if info := snapshot.server_info:
        keys: tuple[tuple[str, FieldKind], ...] = (
            ("name", "name"), ("title", "title"), ("instructions", "instructions"),
        )  # fmt: skip
        yield from _fields(info, keys, server, "/server_info")

    for i, tool in enumerate(snapshot.tools):
        base, loc = f"/tools/{i}", Location(server_id=snapshot.id, tool=tool.name)
        yield from _fields(tool, _ITEM_KEYS, loc, base)
        yield from _walk_schema(tool.input_schema, f"{base}/inputSchema", loc)
        if tool.output_schema:
            yield from _walk_schema(tool.output_schema, f"{base}/outputSchema", loc)

    for i, prompt in enumerate(snapshot.prompts):
        base, loc = f"/prompts/{i}", Location(server_id=snapshot.id, prompt=prompt.name)
        yield from _fields(prompt, _ITEM_KEYS, loc, base)
        for j, arg in enumerate(prompt.arguments):
            yield from _fields(arg, _ITEM_KEYS, loc, f"{base}/arguments/{j}")

    for i, resource in enumerate(snapshot.resources):
        base, loc = f"/resources/{i}", Location(server_id=snapshot.id, resource=resource.uri)
        yield from _fields(resource, (("uri", "uri"), *_ITEM_KEYS), loc, base)


def _walk_schema(node: Any, pointer: str, loc: Location) -> Iterator[TextField]:
    if isinstance(node, list):
        for i, item in enumerate(cast(list[Any], node)):
            yield from _walk_schema(item, f"{pointer}/{i}", loc)
        return
    if not isinstance(node, dict):
        return
    for key, value in cast(dict[str, Any], node).items():
        child = f"{pointer}/{pointer_token(key)}"
        if key in _SCHEMA_TEXT_KEYS and isinstance(value, str):
            yield TextField(_at(loc, child), _SCHEMA_TEXT_KEYS[key], value)
        elif key in _SCHEMA_LIST_KEYS and isinstance(value, list):
            for i, item in enumerate(cast(list[Any], value)):
                if isinstance(item, str):
                    yield TextField(_at(loc, f"{child}/{i}"), _SCHEMA_LIST_KEYS[key], item)
        else:
            if key == "properties" and isinstance(value, dict):
                for name in cast(dict[str, Any], value):
                    yield TextField(
                        _at(loc, f"{child}/{pointer_token(name)}"), "property-name", name
                    )
            yield from _walk_schema(value, child, loc)


def is_variation_selector(cp: int) -> bool:
    return 0xFE00 <= cp <= 0xFE0F or 0xE0100 <= cp <= 0xE01EF


def reveal(text: str) -> str:
    """Make untrusted text safe to print: every control, format or variation-selector character
    becomes a visible ⟨U+XXXX⟩ marker. This also neutralizes ANSI escape sequences (ESC is a control
    character), so a malicious description can't rewrite the terminal while we report on it.
    """
    out: list[str] = []
    for ch in text:
        cp = ord(ch)
        if ch == "\n":
            out.append(ch)
        elif unicodedata.category(ch) in {"Cc", "Cf", "Co", "Cs", "Zl", "Zp"} or (
            is_variation_selector(cp)
        ):
            out.append(f"⟨U+{cp:04X}⟩")
        else:
            out.append(ch)
    return "".join(out)

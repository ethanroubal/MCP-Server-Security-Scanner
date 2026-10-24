"""Bounded schema-derived cases for explicitly selected tools; annotations grant no authority."""

from __future__ import annotations

import copy
from collections.abc import Iterator
from dataclasses import dataclass
from typing import Any, Literal, cast

from mcpiranha.core.models import ToolDef
from mcpiranha.core.text import pointer_token

MAX_CALLS = 24
Variant = Literal["baseline", "path_traversal", "shell_injection", "ssrf"]
PAYLOADS: tuple[tuple[Variant, str], ...] = (
    ("path_traversal", "../../mcpiranha-canary"),
    ("shell_injection", ";echo MCPIRANHA_FUZZ"),
    ("ssrf", "http://192.0.2.1/mcpiranha"),
)


@dataclass(frozen=True)
class InputCase:
    arguments: dict[str, Any]
    variant: Variant = "baseline"
    argument_path: str | None = None


def sample(
    schema: dict[str, Any],
    depth: int = 0,
    *,
    root: dict[str, Any] | None = None,
    budget: list[int] | None = None,
) -> Any:
    root = schema if root is None else root
    budget = [128] if budget is None else budget
    budget[0] -= 1
    if depth > 8 or budget[0] < 0 or any(k in schema for k in ("allOf", "not")):
        raise ValueError("unsupported or recursive schema; supply --invoke-args")
    if "$ref" in schema:
        ref = schema["$ref"]
        if not isinstance(ref, str) or not ref.startswith("#/"):
            raise ValueError("unsupported schema reference; supply --invoke-args")
        value: Any = root
        for key in ref[2:].split("/"):
            value = value[key.replace("~1", "/").replace("~0", "~")]
        return sample(value, depth + 1, root=root, budget=budget)
    for keyword in ("oneOf", "anyOf"):
        if keyword in schema:
            choices = [s for s in schema[keyword] if s.get("type") != "null"]
            if not choices:
                return None
            return sample(choices[0], depth + 1, root=root, budget=budget)
    if "const" in schema:
        return schema["const"]
    if values := schema.get("enum"):
        return values[0]
    kind = schema.get("type", "object" if "properties" in schema else None)
    if kind == "object":
        properties = schema.get("properties", {})
        if len(schema.get("required", [])) > 64:
            raise ValueError("too many required properties; supply --invoke-args")
        return {
            name: sample(properties[name], depth + 1, root=root, budget=budget)
            for name in schema.get("required", [])
        }
    if kind == "string":
        if schema.get("format") or schema.get("pattern"):
            raise ValueError("formatted input requires --invoke-args")
        minimum, maximum = schema.get("minLength", 0), schema.get("maxLength", 128)
        if minimum > 128 or minimum > maximum:
            raise ValueError("string constraints require --invoke-args")
        return "mcpiranha-test".ljust(minimum, "x")[: max(0, min(128, maximum))]
    if kind in ("integer", "number"):
        if any(k in schema for k in ("exclusiveMinimum", "exclusiveMaximum", "multipleOf")):
            raise ValueError("numeric constraints require --invoke-args")
        return schema.get("minimum", min(0, schema.get("maximum", 0)))
    if kind == "boolean":
        return False
    if kind == "null":
        return None
    if kind == "array":
        count = schema.get("minItems", 0)
        if count > 4:
            raise ValueError("array constraints require --invoke-args")
        return [
            sample(schema.get("items", {}), depth + 1, root=root, budget=budget)
            for _ in range(count)
        ]
    raise ValueError("cannot synthesize this schema; supply --invoke-args")


def _strings(value: Any, path: tuple[str | int, ...] = ()) -> Iterator[tuple[str | int, ...]]:
    if len(path) > 8:
        return
    if isinstance(value, str):
        yield path
    elif isinstance(value, dict):
        for key, item in list(cast(dict[str, Any], value).items())[:64]:
            yield from _strings(item, (*path, key))
    elif isinstance(value, list):
        for index, item in enumerate(cast(list[Any], value)[:4]):
            yield from _strings(item, (*path, index))


def cases(tool: ToolDef, arguments: dict[str, Any] | None, fuzz: bool) -> list[InputCase]:
    base = sample(tool.input_schema or {"type": "object"}) if arguments is None else arguments
    if not isinstance(base, dict):
        raise ValueError("tool input must be an object")
    base = cast(dict[str, Any], base)
    result = [InputCase(base)]
    if fuzz:
        for path in _strings(base):
            for variant, payload in PAYLOADS:
                changed = copy.deepcopy(base)
                current: Any = changed
                for key in path[:-1]:
                    current = current[key]
                current[path[-1]] = payload
                result.append(
                    InputCase(changed, variant, "/" + "/".join(pointer_token(key) for key in path))
                )
                if len(result) >= MAX_CALLS:
                    return result
    return result


def inputs(tool: ToolDef, arguments: dict[str, Any] | None, fuzz: bool) -> list[dict[str, Any]]:
    return [case.arguments for case in cases(tool, arguments, fuzz)]

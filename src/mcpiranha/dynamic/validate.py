"""Validate baseline inputs offline in a resource-bounded worker, never in the scanner loop.

Untrusted schemas may contain costly regular expressions or recursion. No remote references
are retrieved. Error messages expose only schema keywords and argument paths, not values.
"""

from __future__ import annotations

import importlib
import json
import sys
from pathlib import Path
from typing import Any, cast

import anyio

MAX_INPUT = 512_000
VALIDATION_TIMEOUT = 2.0


def _bounded(value: Any, depth: int = 0, budget: list[int] | None = None) -> None:
    budget = [4096] if budget is None else budget
    budget[0] -= 1
    if depth > 32 or budget[0] < 0:
        raise ValueError("schema or input exceeds validation limits")
    if isinstance(value, dict):
        for item in cast(dict[str, Any], value).values():
            _bounded(item, depth + 1, budget)
    elif isinstance(value, list):
        for item in cast(list[Any], value):
            _bounded(item, depth + 1, budget)


def worker() -> None:
    try:
        if sys.platform == "linux":
            import resource

            resource.setrlimit(resource.RLIMIT_AS, (256 * 1024 * 1024, 256 * 1024 * 1024))
            resource.setrlimit(resource.RLIMIT_CPU, (1, 1))
        payload = sys.stdin.buffer.read(MAX_INPUT + 1)
        if len(payload) > MAX_INPUT:
            raise ValueError("validation input exceeds limit")
        data: dict[str, Any] = json.loads(payload)
        schema, arguments = data["schema"], data["arguments"]
        _bounded(schema)
        _bounded(arguments)
        # Known dialects only: an unknown URI must not silently fall back to a different draft.
        dialect = schema.get("$schema", "https://json-schema.org/draft/2020-12/schema")
        if not isinstance(dialect, str):
            raise ValueError("unsupported JSON Schema dialect")
        dialect = dialect.removesuffix("#").replace("http://", "https://", 1)
        classes = {
            "https://json-schema.org/draft-07/schema": "Draft7Validator",
            "https://json-schema.org/draft/2019-09/schema": "Draft201909Validator",
            "https://json-schema.org/draft/2020-12/schema": "Draft202012Validator",
        }
        if dialect not in classes:
            raise ValueError("unsupported JSON Schema dialect")
        # Imported only by the isolated worker, keeping scanner startup light.
        validation = importlib.import_module("jsonschema")
        references = importlib.import_module("referencing")
        validator = getattr(validation, classes[dialect])
        validator.check_schema(schema)
        error = next(validator(schema, registry=references.Registry()).iter_errors(arguments), None)
        if error is not None:
            pointer = "/" + "/".join(
                str(k).replace("~", "~0").replace("/", "~1") for k in error.absolute_path
            )
            print(json.dumps({"error": f"baseline violates {error.validator} at {pointer[:200]}"}))
        else:
            print('{"valid": true}')
    except ValueError as exc:
        print(json.dumps({"error": str(exc)[:200]}))
    except Exception:
        print('{"error": "invalid, recursive, or unresolved input schema"}')


async def baseline(schema: dict[str, Any], arguments: dict[str, Any]) -> None:
    payload = json.dumps({"schema": schema or {"type": "object"}, "arguments": arguments}).encode()
    if len(payload) > MAX_INPUT:
        raise ValueError("validation input exceeds limit")
    try:
        with anyio.fail_after(VALIDATION_TIMEOUT):
            result = await anyio.run_process(
                [sys.executable, "-I", str(Path(__file__).resolve())], input=payload, check=False
            )
        if result.returncode != 0:
            raise ValueError("baseline validation exceeded resource limits or failed")
        answer = json.loads(result.stdout)
        if not answer.get("valid"):
            raise ValueError(answer.get("error", "baseline input is invalid"))
    except TimeoutError as exc:
        raise ValueError("baseline validation timed out") from exc


if __name__ == "__main__":
    worker()

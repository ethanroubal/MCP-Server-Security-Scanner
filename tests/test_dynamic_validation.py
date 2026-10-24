"""Baseline schema validation must stay offline, bounded and free of argument values in errors."""

from __future__ import annotations

from pathlib import Path
from typing import Any

import anyio
import pytest

from mcpiranha.dynamic.validate import baseline


def test_valid_baseline_and_invalid_explicit_arguments() -> None:
    schema = {
        "type": "object",
        "required": ["count"],
        "additionalProperties": False,
        "properties": {"count": {"type": "integer", "minimum": 1}},
    }
    anyio.run(baseline, schema, {"count": 1})
    for arguments in ({"count": 0}, {"count": "private-value-123"}, {"count": 1, "extra": True}):
        with pytest.raises(ValueError) as error:
            anyio.run(baseline, schema, arguments)
        assert "private-value" not in str(error.value)


def test_invalid_oneof_and_remote_references_cannot_be_treated_as_valid() -> None:
    arguments: dict[str, Any] = {}
    with pytest.raises(ValueError, match="oneOf"):
        anyio.run(baseline, {"oneOf": [{"type": "object"}, {"type": "object"}]}, arguments)
    with pytest.raises(ValueError):
        anyio.run(baseline, {"$ref": "http://127.0.0.1:9/not-fetched"}, arguments)
    with pytest.raises(ValueError):
        anyio.run(baseline, {"$ref": "#"}, arguments)


def test_expensive_patterns_are_bounded_and_do_not_block_the_scanner() -> None:
    schema = {"type": "object", "properties": {"text": {"pattern": "^(a+)+$"}}}
    with pytest.raises(ValueError, match=r"resource|timed out"):
        anyio.run(baseline, schema, {"text": "a" * 100 + "!"})


@pytest.mark.parametrize(
    "dialect",
    [
        "http://json-schema.org/draft-07/schema#",
        "https://json-schema.org/draft/2019-09/schema",
        "https://json-schema.org/draft/2020-12/schema",
    ],
)
def test_remote_schema_cannot_make_a_network_request(dialect: str) -> None:
    import threading
    from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

    requests: list[str] = []

    class Handler(BaseHTTPRequestHandler):
        def do_GET(self) -> None:
            requests.append(self.path)
            self.send_response(200)
            self.end_headers()
            self.wfile.write(b'{"type":"object"}')

        def log_message(self, format: str, *args: object) -> None:
            pass

    server = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    try:
        with pytest.raises(ValueError):
            anyio.run(
                baseline,
                {"$schema": dialect, "$ref": f"http://127.0.0.1:{server.server_port}/schema"},
                dict[str, Any](),
            )
        assert requests == []
    finally:
        server.shutdown()
        server.server_close()
        thread.join(timeout=5)


def test_invalid_input_never_reaches_tool_invocation() -> None:
    from mcpiranha.acquire import ConnectOptions, connect_one
    from tests.test_dynamic import snapshot

    found = anyio.run(
        connect_one,
        snapshot(),
        ConnectOptions(
            sandbox="none",
            observe_seconds=0,
            invoke=("echo",),
            invoke_args={"text": 123},
            fuzz=True,
        ),
    )
    assert found.probes == [] and not [c for c in found.content if c.kind == "tool"]
    assert any(e.kind == "probe_error" and "type" in e.detail for e in found.observations)


def test_validation_worker_does_not_import_from_scanned_directory(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    package = tmp_path / "mcpiranha"
    package.mkdir()
    (package / "__init__.py").write_text("raise RuntimeError('untrusted scanner package imported')")
    (tmp_path / "jsonschema.py").write_text("raise RuntimeError('untrusted validator imported')")
    monkeypatch.chdir(tmp_path)
    monkeypatch.setenv("PYTHONPATH", str(tmp_path))
    anyio.run(baseline, {"type": "object"}, dict[str, Any]())


@pytest.mark.parametrize(
    "dialect",
    [
        "http://json-schema.org/draft-07/schema#",
        "https://json-schema.org/draft/2019-09/schema#",
        "https://json-schema.org/draft/2020-12/schema",
    ],
)
def test_supported_dialects_are_validated(dialect: str) -> None:
    schema = {
        "$schema": dialect,
        "type": "object",
        "properties": {"value": {"type": "string"}},
        "required": ["value"],
    }
    anyio.run(baseline, schema, {"value": "valid"})
    with pytest.raises(ValueError, match="type"):
        anyio.run(baseline, schema, {"value": 123})

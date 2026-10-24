"""Opt-in invocation and behavioral evidence, including a real isolated Docker fixture."""

from __future__ import annotations

import functools
import json
import os
import sys
from pathlib import Path
from typing import Any

import anyio
import pytest
from typer.testing import CliRunner

from mcpiranha import acquire
from mcpiranha.acquire import ConnectOptions, connect_one
from mcpiranha.acquire import sandbox as sb
from mcpiranha.acquire.listing import EnumerationError
from mcpiranha.cli import app
from mcpiranha.core.models import Launch, Origin, ServerSnapshot, ToolDef
from mcpiranha.core.pipeline import scan
from mcpiranha.dynamic.invoke import MAX_CALLS, inputs, sample
from mcpiranha.dynamic.runtime import observations
from mcpiranha.rules import load_rules

ROOT = Path(__file__).resolve().parent.parent
PROBE = ROOT / "fixtures/servers/dynamic_probe.py"


def snapshot() -> ServerSnapshot:
    return ServerSnapshot(
        id="probe",
        name="probe",
        origin=Origin(kind="path", ref=str(PROBE)),
        tools_listed=False,
        launch=Launch(transport="stdio", command=sys.executable, args=[str(PROBE)]),
    )


def test_tool_output_is_only_read_with_explicit_invocation() -> None:
    before = anyio.run(connect_one, snapshot(), ConnectOptions(sandbox="none", observe_seconds=0))
    assert not before.content
    after = anyio.run(
        connect_one,
        snapshot(),
        ConnectOptions(sandbox="none", observe_seconds=0, invoke=("echo",), fuzz=True),
    )
    assert len([c for c in after.content if c.kind == "tool"]) == 4
    result = scan([after], load_rules(plugins=False))
    assert {"MCP-TP-003", "MCP-TP-004", "MCP-TP-005"} <= {f.rule_id for f in result.findings}
    assert all(f.location.tool == "echo" for f in result.findings)
    assert not any(o.kind == "probe_error" for o in after.observations)


def test_unknown_tool_records_partial_scan() -> None:
    after = anyio.run(
        connect_one,
        snapshot(),
        ConnectOptions(sandbox="none", observe_seconds=0, invoke=("missing",)),
    )
    assert any(o.kind == "probe_error" and "not listed" in o.detail for o in after.observations)


@pytest.mark.parametrize(
    "args",
    [
        ["--fuzz"],
        ["--invoke", "echo"],
        ["--dynamic"],
        ["--connect", "--fuzz"],
        ["--connect", "--invoke-args", "{}"],
        ["--connect", "--dynamic", "--sandbox", "none"],
        ["--connect", "--invoke", "echo", "--invoke-args", "[]"],
    ],
)
def test_cli_rejects_invalid_probe_options(args: list[str]) -> None:
    result = CliRunner().invoke(app, ["scan", *args, "--offline"])
    assert result.exit_code == 2, result.output


def test_schema_and_fuzz_caps() -> None:
    assert sample(
        {
            "type": "object",
            "required": ["count"],
            "properties": {"count": {"type": "integer", "minimum": 2}},
        }
    ) == {"count": 2}
    with pytest.raises(ValueError, match="unsupported"):
        sample({"$ref": "#"})
    cases = inputs(ToolDef(name="test"), {str(i): "x" for i in range(100)}, True)
    assert len(cases) == MAX_CALLS


def test_trace_rules_and_phases() -> None:
    events = observations(
        "\n".join(
            [
                '1 1800000000.000001 open("/tmp/mcpiranha-home/.ssh/id_rsa", O_WRONLY) = 3',
                '1 1800000000.000002 open("/tmp/mcpiranha-home/.ssh/id_rsa", O_RDONLY) = 3',
                "1 1800000001.000001 connect(3, {sa_family=AF_INET, sin_port=htons(443)}, 16) = -1",
                '1 1800000002.000001 execve("/bin/sh", ["sh", "-c", "echo test"], []) = 0',
                '1 1800000002.000002 open("/tmp/mcpiranha-home/.env", O_RDONLY) = -1 ENOENT',
            ]
        ),
        [(1800000001, "listing"), (1800000002, "invocation")],
    )
    assert [o.phase for o in events] == [
        "startup",
        "startup",
        "listing",
        "invocation",
        "invocation",
    ]
    result = scan(
        [snapshot().model_copy(update={"observations": events})], load_rules(plugins=False)
    )
    findings = {f.rule_id: f for f in result.findings}
    assert {"MCP-DY-003", "MCP-DY-004", "MCP-DY-005"} <= findings.keys()
    assert findings["MCP-DY-003"].severity == "critical"
    assert all(f.detector == "dynamic" for f in findings.values())


def test_invocation_failure_is_never_replayed(monkeypatch: pytest.MonkeyPatch) -> None:

    calls: list[str] = []

    async def fail(transport: Any, **kwargs: Any) -> Any:
        calls.append(kwargs["handshake"])
        kwargs["phase_changed"]("invocation")
        raise EnumerationError("transport lost after side effect")

    monkeypatch.setattr(acquire, "enumerate_server", fail)
    prepared = sb.Prepared(lambda: None, "fake")  # type: ignore[arg-type]
    with pytest.raises(EnumerationError):
        anyio.run(  # pyright: ignore[reportPrivateUsage]
            acquire._enumerate_with_fallback,  # pyright: ignore[reportPrivateUsage]
            prepared,
            ConnectOptions(invoke=("echo",)),
        )
    assert calls == ["auto"]


@pytest.mark.skipif(
    os.environ.get("MCPIRANHA_DOCKER_TESTS") != "1", reason="needs Docker and network"
)
def test_real_dynamic_docker(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    image = "mcpiranha-dynamic-fixture:test"
    (tmp_path / "probe.py").write_text(PROBE.read_text())
    (tmp_path / "Dockerfile").write_text(
        'FROM python:3.12-slim\nCOPY probe.py /probe.py\nENTRYPOINT ["python", "/probe.py"]\n'
    )
    anyio.run(functools.partial(sb.docker, "build", "-q", "-t", image, str(tmp_path), timeout=300))
    original = sb._docker  # pyright: ignore[reportPrivateUsage]

    async def local_image(*args: str, timeout: float) -> str:
        # This test image is intentionally never published; skip only its pull.
        if args == ("pull", image):
            return ""
        return await original(*args, timeout=timeout)

    monkeypatch.setattr(sb, "_docker", local_image)
    target = snapshot().model_copy(
        update={"launch": Launch(transport="stdio", command="docker", args=["run", "-i", image])}
    )
    after = anyio.run(
        connect_one,
        target,
        ConnectOptions(dynamic=True, timeout=90, observe_seconds=0, invoke=("echo",)),
    )
    result = scan([after], load_rules(plugins=False))
    assert {"MCP-DY-003", "MCP-DY-004", "MCP-TP-004"} <= {f.rule_id for f in result.findings}, (
        "\n".join(
            o.detail for o in after.observations if ".ssh" in o.detail or o.kind == "probe_error"
        )
    )
    assert not [o for o in after.observations if o.kind == "probe_error"]
    assert any("egress proxy:" in o.detail and "denied" in o.detail for o in after.observations)
    assert any(o.kind == "file_open" for o in after.observations)


def test_strict_scan_fails_on_incomplete_invocation(tmp_path: Path) -> None:
    config = tmp_path / ".mcp.json"
    config.write_text(
        json.dumps({"mcpServers": {"probe": {"command": sys.executable, "args": [str(PROBE)]}}})
    )
    result = CliRunner().invoke(
        app,
        [
            "scan",
            str(config),
            "--offline",
            "--connect",
            "--sandbox",
            "none",
            "--invoke",
            "missing",
            "--strict",
            "-f",
            "json",
        ],
    )
    assert result.exit_code == 2, result.output
    assert "incomplete behavioral scan" in json.loads(result.stdout)["warnings"][0]


def test_instrumentation_uses_trusted_helper_and_cleans_up(monkeypatch: pytest.MonkeyPatch) -> None:
    from mcpiranha.dynamic.runtime import instrument

    calls: list[tuple[str, ...]] = []
    builds: list[str] = []

    async def docker(*args: str, timeout: float) -> str:
        calls.append(args)
        if args[:2] == ("image", "inspect"):
            return '{"Entrypoint":["python"],"Cmd":["/server.py"]}'
        if args[0] == "build":
            builds.append((Path(args[-1]) / "Dockerfile").read_text())
        if args[0] == "logs":
            return '{"time":1800000000,"target":"probe.invalid:443","allowed":false}'
        return ""

    monkeypatch.setattr(sb, "docker", docker)
    command = [
        "docker",
        "run",
        "--rm",
        "-i",
        "--network",
        "none",
        "--name",
        "probe",
        "--cap-drop",
        "ALL",
        "untrusted/server:1",
    ]
    prepared = sb.Prepared(lambda: None, "fake", command=command)  # type: ignore[arg-type]
    anyio.run(functools.partial(instrument, prepared, allow_network=False))
    assert len(builds) == 1 and "FROM python:" in builds[0]
    assert "untrusted/server" not in builds[0]
    assert command[-3:] == ["untrusted/server:1", "python", "/server.py"]
    assert "--internal" in next(c for c in calls if c[:2] == ("network", "create"))
    assert "HTTP_PROXY=http://mcpiranha-egress:8080" in command
    assert "--rm" not in command  # retain until trace collection
    assert any(a.endswith(":/mcpiranha:ro") for a in command)
    assert not any(":/trace" in a for a in command)
    assert "--cap-add" not in command
    assert command[command.index("--entrypoint") + 1] == "/mcpiranha/launcher"
    observed = anyio.run(prepared.collect)
    assert any("denied" in o.detail for o in observed)
    anyio.run(prepared.cleanup)
    for call in calls:
        if call[:2] == ("volume", "create"):
            assert ("volume", "rm", "-f", call[2]) in calls
        if call[:2] == ("network", "create"):
            assert ("network", "rm", call[-1]) in calls


def test_proxy_default_deny_and_explicit_forwarding(monkeypatch: pytest.MonkeyPatch) -> None:
    import http.client
    import socket
    import threading
    from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

    from mcpiranha.dynamic.proxy import Proxy

    class Destination(BaseHTTPRequestHandler):
        def do_GET(self) -> None:
            self.send_response(200)
            self.end_headers()
            self.wfile.write(b"local fixture only")

        def log_message(self, format: str, *args: object) -> None:
            pass

    destination = ThreadingHTTPServer(("127.0.0.1", 0), Destination)
    proxy = ThreadingHTTPServer(("127.0.0.1", 0), Proxy)
    threads = [threading.Thread(target=s.serve_forever, daemon=True) for s in (destination, proxy)]
    for thread in threads:
        thread.start()
    try:
        monkeypatch.delenv("ALLOW_NETWORK", raising=False)
        connection = http.client.HTTPConnection("127.0.0.1", proxy.server_port, timeout=5)
        connection.request("GET", f"http://127.0.0.1:{destination.server_port}/")
        response = connection.getresponse()
        assert response.status == 403
        response.read()
        connection.close()
        monkeypatch.setenv("ALLOW_NETWORK", "1")
        connection = http.client.HTTPConnection("127.0.0.1", proxy.server_port, timeout=5)
        connection.request("GET", f"http://127.0.0.1:{destination.server_port}/")
        response = connection.getresponse()
        assert response.status == 200 and response.read() == b"local fixture only"
        connection.close()
        # HTTPS proxying uses an opaque CONNECT tunnel, exercised with local HTTP bytes.
        with socket.create_connection(("127.0.0.1", proxy.server_port), timeout=5) as tunnel:
            tunnel.sendall(f"CONNECT 127.0.0.1:{destination.server_port} HTTP/1.0\r\n\r\n".encode())
            response_bytes = b""
            while b"\r\n\r\n" not in response_bytes:
                response_bytes += tunnel.recv(4096)
            assert b"200" in response_bytes
            tunnel.sendall(b"GET / HTTP/1.0\r\n\r\n")
            data = b""
            while block := tunnel.recv(4096):
                data += block
            assert b"local fixture only" in data
    finally:
        for server in (destination, proxy):
            server.shutdown()
            server.server_close()
        for thread in threads:
            thread.join(timeout=5)


def test_invocation_keeps_existing_content_at_capacity(monkeypatch: pytest.MonkeyPatch) -> None:
    from mcpiranha.acquire import listing
    from mcpiranha.core.models import FetchedContent

    async def fill(client: Any, result: listing.Enumeration, *, timeout: float) -> None:
        result.content = [
            FetchedContent(kind="resource", ref=f"test://{i}", text="existing")
            for i in range(listing.MAX_CONTENT_ITEMS)
        ]

    monkeypatch.setattr(listing, "_fetch_content", fill)
    after = anyio.run(
        connect_one, snapshot(), ConnectOptions(sandbox="none", observe_seconds=0, invoke=("echo",))
    )
    assert len([c for c in after.content if c.kind == "resource"]) == listing.MAX_CONTENT_ITEMS
    assert len([c for c in after.content if c.kind == "tool"]) == 1

"""The Docker sandbox's commands, checked without a Docker daemon by faking the docker CLI.

Set MCPIRANHA_DOCKER_TESTS=1 to also run a real server in a real sandbox (needs Docker and network).
"""

from __future__ import annotations

import io
import os
import sys

import anyio
import pytest
from pydantic import SecretStr

from mcpiranha.acquire import ConnectOptions, connect_one
from mcpiranha.acquire import sandbox as sb
from mcpiranha.core.launch import package_ref
from mcpiranha.core.models import Launch, Origin, ServerSnapshot

RESTRICTIONS = [("--network", "none"), ("--cap-drop", "ALL"),
                ("--security-opt", "no-new-privileges"), ("--user", "1000:1000")]  # fmt: skip


class FakeDocker:
    def __init__(self, fetch_output: str = "MCPIRANHA_BIN=dist/index.js\n") -> None:
        self.calls: list[tuple[str, ...]] = []
        self.fetch_output = fetch_output

    async def __call__(self, *args: str, timeout: float) -> str:
        self.calls.append(args)
        return self.fetch_output if args[0] == "run" else ""


def _prepare(monkeypatch: pytest.MonkeyPatch, *argv: str, env: dict[str, str] | None = None,
             fake: FakeDocker | None = None) -> tuple[sb.Prepared, FakeDocker]:  # fmt: skip
    fake = fake or FakeDocker()
    monkeypatch.setattr(sb, "_docker", fake)
    launch = Launch(transport="stdio", command=argv[0], args=list(argv[1:]),
                    env={k: SecretStr(v) for k, v in (env or {}).items()})  # fmt: skip
    prepared = anyio.run(lambda: sb.prepare(launch, sandbox="docker", real_credentials=False,
                                             errlog=io.StringIO(), environ={}))  # fmt: skip
    return prepared, fake


def _has(argv: list[str], *expected: str) -> bool:
    joined = "\x00".join(argv)
    return "\x00".join(expected) in joined


def test_npm_server_runs_offline_and_unprivileged(monkeypatch: pytest.MonkeyPatch) -> None:
    prepared, fake = _prepare(monkeypatch, "npx", "-y", "@acme/mcp@1.2.3", "--root", "/data",
                              env={"API_KEY": "real-secret"})  # fmt: skip
    install = next(c for c in fake.calls if c[0] == "run")
    assert "--network" not in install  # fetch needs the registry...
    assert "--ignore-scripts" in " ".join(install)  # ...but runs no install scripts
    assert "@acme/mcp@1.2.3" in install

    command = prepared.command or []
    for flag, value in RESTRICTIONS:
        assert _has(command, flag, value), flag
    assert "--read-only" in command
    assert any(a.endswith(":/work:ro") for a in command)
    assert command[-3:] == ["/work/node_modules/@acme/mcp/dist/index.js", "--root", "/data"]
    assert "API_KEY=mcpiranha-dummy-value" in command
    assert "real-secret" not in " ".join(command)


def test_volume_is_removed_after_use(monkeypatch: pytest.MonkeyPatch) -> None:
    prepared, fake = _prepare(monkeypatch, "npx", "-y", "pkg")
    prepared.connect()  # each attempt gets its own container name (handshake fallback)
    prepared.connect()
    anyio.run(prepared.cleanup)
    assert any(c[:2] == ("volume", "rm") for c in fake.calls)
    removed = [c[2] for c in fake.calls if c[:2] == ("rm", "-f")]
    assert len(removed) == 2 and removed[0].endswith("-0") and removed[1].endswith("-1")


def test_pypi_server_installs_wheels_only(monkeypatch: pytest.MonkeyPatch) -> None:
    prepared, fake = _prepare(monkeypatch, "uvx", "--from", "mcp-server-git@1.0.0", "git-mcp",
                              "--repository", "/repo")  # fmt: skip
    install = next(c for c in fake.calls if c[0] == "run")
    assert "--only-binary :all:" in " ".join(install)
    assert "mcp-server-git==1.0.0" in install
    command = prepared.command or []
    assert _has(command, "--entrypoint", "/work/venv/bin/git-mcp")
    assert command[-2:] == ["--repository", "/repo"]


def test_docker_image_server_drops_config_flags(monkeypatch: pytest.MonkeyPatch) -> None:
    prepared, fake = _prepare(
        monkeypatch, "docker", "run", "-i", "--rm", "--privileged", "-v", "/:/host",
        "-e", "TOKEN", "ghcr.io/acme/mcp:2", "serve",
    )  # fmt: skip
    assert ("pull", "ghcr.io/acme/mcp:2") in fake.calls
    command = prepared.command or []
    assert "--privileged" not in command and "/:/host" not in command
    assert _has(command, "--network", "none")
    assert "TOKEN=mcpiranha-dummy-value" in command
    assert command[-2:] == ["ghcr.io/acme/mcp:2", "serve"]


def test_local_files_cannot_be_sandboxed(monkeypatch: pytest.MonkeyPatch) -> None:
    with pytest.raises(sb.SandboxError, match="--sandbox none"):
        _prepare(monkeypatch, "node", "./server.js")


def test_package_bin_cannot_escape(monkeypatch: pytest.MonkeyPatch) -> None:
    with pytest.raises(sb.SandboxError, match="outside itself"):
        _prepare(
            monkeypatch, "npx", "-y", "evil", fake=FakeDocker("MCPIRANHA_BIN=../../../bin/sh\n")
        )


def test_pypi_requirement() -> None:
    def requirement(*argv: str) -> str:
        ref = package_ref(Launch(transport="stdio", command=argv[0], args=list(argv[1:])))
        assert ref is not None
        return sb.pypi_requirement(ref)

    assert requirement("uvx", "pkg") == "pkg"
    assert requirement("uvx", "pkg@1.2") == "pkg==1.2"
    assert requirement("uvx", "pkg>=1,<2") == "pkg>=1,<2"
    assert requirement("uvx", "--from", "pkg[mcp-docker]", "pkg") == "pkg[mcp-docker]"
    assert requirement("uvx", "pkg[cli]==2.0") == "pkg[cli]==2.0"


def test_missing_docker_daemon_explains_the_fix(monkeypatch: pytest.MonkeyPatch) -> None:
    async def no_daemon(*args: str, timeout: float) -> str:
        raise sb.SandboxError("Cannot connect to the Docker daemon")

    monkeypatch.setattr(sb, "_docker", no_daemon)
    with pytest.raises(sb.SandboxError, match="start Docker Desktop"):
        anyio.run(sb.docker_available)


@pytest.mark.skipif(os.environ.get("MCPIRANHA_DOCKER_TESTS") != "1",
                    reason="set MCPIRANHA_DOCKER_TESTS=1 (needs Docker and network)")  # fmt: skip
def test_real_docker_sandbox() -> None:
    snapshot = ServerSnapshot(
        id="target:npm:@modelcontextprotocol/server-everything",
        name="everything",
        origin=Origin(kind="npm", ref="npm:@modelcontextprotocol/server-everything"),
        launch=Launch(
            transport="stdio", command="npx", args=["-y", "@modelcontextprotocol/server-everything"]
        ),
        tools_listed=False,
    )
    listed = anyio.run(connect_one, snapshot, ConnectOptions(timeout=120))
    assert listed.tools, sys.stderr


def test_resolved_versions_are_reported(monkeypatch: pytest.MonkeyPatch) -> None:
    output = "MCPIRANHA_BIN=index.js\nMCPIRANHA_VERSION=4.2.0\n"
    npm, _ = _prepare(monkeypatch, "npx", "-y", "pkg", fake=FakeDocker(output))
    assert npm.resolved is not None and (npm.resolved.name, npm.resolved.version) == (
        "pkg",
        "4.2.0",
    )

    pypi, fake = _prepare(monkeypatch, "uvx", "mcp-server-git",
                          fake=FakeDocker("MCPIRANHA_VERSION=2025.1.14\n"))  # fmt: skip
    assert pypi.resolved is not None and pypi.resolved.version == "2025.1.14"
    install = next(c for c in fake.calls if c[0] == "run")
    assert any(a.startswith(f"{sb.UV_CACHE_VOLUME}:") for a in install)  # shared cache

    class Inspect(FakeDocker):
        async def __call__(self, *args: str, timeout: float) -> str:
            self.calls.append(args)
            return '["ghcr.io/acme/mcp@sha256:abc123"]' if args[:2] == ("image", "inspect") else ""

    image, _ = _prepare(monkeypatch, "docker", "run", "-i", "ghcr.io/acme/mcp:2", fake=Inspect())
    assert image.resolved is not None and image.resolved.version == "sha256:abc123"


def test_npm_fetch_uses_the_shared_cache(monkeypatch: pytest.MonkeyPatch) -> None:
    _, fake = _prepare(monkeypatch, "npx", "-y", "pkg")
    install = next(c for c in fake.calls if c[0] == "run")
    assert f"{sb.NPM_CACHE_VOLUME}:/cache" in install


class Scripted(FakeDocker):
    """Fails `docker <verb>` calls whose arguments contain `fail_on`, once each."""

    def __init__(self, fail_on: dict[str, str], output: str = "") -> None:
        super().__init__(output)
        self.fail_on = dict(fail_on)

    async def __call__(self, *args: str, timeout: float) -> str:
        self.calls.append(args)
        for needle, error in list(self.fail_on.items()):
            if needle in args:
                del self.fail_on[needle]
                raise sb.SandboxError(error)
        return self.fetch_output if args[0] in ("run", "image") else ""


def test_python_version_fallback(monkeypatch: pytest.MonkeyPatch) -> None:
    wrapped = "Because the current Python version (3.12.12) does not satisfy\n      Python>=3.13"
    fake = Scripted({sb.UV_IMAGE: f"docker run failed: {wrapped}"},
                    "MCPIRANHA_VERSION=8.7.0\nMCPIRANHA_SCRIPTS=ha-mcp\n")  # fmt: skip
    prepared, _ = _prepare(monkeypatch, "uvx", "ha-mcp==8.7.0", fake=fake)
    assert sb.UV_IMAGE_NEWER in (prepared.command or [])  # runs on the image that installed it


def test_arm_fallback_pulls_amd64(monkeypatch: pytest.MonkeyPatch) -> None:
    fake = Scripted({"pull": "docker pull failed: no matching manifest for linux/arm64/v8"})
    prepared, _ = _prepare(monkeypatch, "docker", "run", "-i", "acme/mcp:1", fake=fake)
    assert ("pull", "--platform", "linux/amd64", "acme/mcp:1") in fake.calls
    assert _has(prepared.command or [], "--platform", "linux/amd64")


def test_pypi_executable_comes_from_console_scripts(monkeypatch: pytest.MonkeyPatch) -> None:
    out = "MCPIRANHA_VERSION=0.51.5\nMCPIRANHA_SCRIPTS=ouroboros,ouroboros-mcp\n"
    prepared, _ = _prepare(monkeypatch, "uvx", "ouroboros-ai==0.51.5", "mcp", "serve",
                           fake=FakeDocker(out))  # fmt: skip
    assert _has(prepared.command or [], "--entrypoint", "/work/venv/bin/ouroboros-mcp")


def test_pick_script() -> None:
    assert sb.pick_script("tool", ["tool", "other"]) == "tool"
    assert sb.pick_script("pkg", ["only-one"]) == "only-one"
    assert sb.pick_script("pkg", ["cli", "pkg-mcp"]) == "pkg-mcp"
    assert sb.pick_script("pkg", []) == "pkg"
    with pytest.raises(sb.SandboxError, match="isn't one of"):
        sb.pick_script("pkg", ["a", "b"])


def test_package_servers_get_a_writable_workdir(monkeypatch: pytest.MonkeyPatch) -> None:
    prepared, _ = _prepare(monkeypatch, "npx", "-y", "pkg")
    command = prepared.command or []
    assert _has(command, "--workdir", "/tmp") and "--read-only" in command
    assert "TMPDIR=/tmp" in command


def test_opt_ins(monkeypatch: pytest.MonkeyPatch) -> None:
    fake = FakeDocker()
    monkeypatch.setattr(sb, "_docker", fake)
    launch = Launch(transport="stdio", command="npx", args=["-y", "pkg"])
    prepared = anyio.run(lambda: sb.prepare(
        launch, sandbox="docker", real_credentials=False, errlog=io.StringIO(), environ={},
        allow_network=True, allow_install_scripts=True))  # fmt: skip
    install = " ".join(next(c for c in fake.calls if c[0] == "run"))
    assert "MCPIRANHA_IGNORE_SCRIPTS= " in install + " "  # scripts allowed: flag left empty
    assert "--network" not in (prepared.command or [])


def test_uvx_with_requirements_are_installed(monkeypatch: pytest.MonkeyPatch) -> None:
    _, fake = _prepare(monkeypatch, "uvx", "--with", "edgartools[ai]==5.62.0", "edgartools==5.62.0",
                       "mcp")  # fmt: skip
    install = next(c for c in fake.calls if c[0] == "run")
    assert install[-3:] == ("edgartools==5.62.0", "edgartools", "edgartools[ai]==5.62.0")

"""Start a server so it can be enumerated, without trusting it.

Docker sandbox (the default), in two phases:

1. Fetch: download the package into a throwaway volume, with network access but without running
   it. npm installs use --ignore-scripts and PyPI installs accept wheels only, so no package
   code runs during installation either.
2. Run: start the server from that volume, read-only, with no network, no capabilities, no
   privilege escalation, a non-root user, resource limits, and fake values for its env vars.

Docker-image servers are pulled, then run with the same restrictions instead of the flags from
their config. Servers that run local files (`node ./server.js`) can't be sandboxed this way;
`--sandbox none` runs them, and everything else, directly on this machine.

Remote servers aren't started at all; they're only connected to.
"""

from __future__ import annotations

import contextlib
import json
import os
import posixpath
import re
import uuid
from collections.abc import Awaitable, Callable, Mapping
from dataclasses import dataclass, field
from typing import Any, Literal, TextIO, cast

import anyio
import httpx2
from mcp.client import Transport
from mcp.client.sse import sse_client
from mcp.client.stdio import StdioServerParameters, get_default_environment, stdio_client
from mcp.client.streamable_http import streamable_http_client

from mcpscan.acquire.oauth import LoopbackCallback, OpenUrl, oauth_provider
from mcpscan.core.launch import PackageRef, command_line, docker_run, package_ref
from mcpscan.core.models import Launch, PackageMeta

Sandbox = Literal["docker", "none"]

DUMMY_VALUE = "mcpscan-dummy-value"
NODE_IMAGE = os.environ.get("MCPSCAN_NODE_IMAGE", "node:22-bookworm-slim")
UV_IMAGE = os.environ.get("MCPSCAN_UV_IMAGE", "ghcr.io/astral-sh/uv:python3.12-bookworm-slim")
FETCH_TIMEOUT = 300.0
PULL_TIMEOUT = 600.0
# Package caches shared by every fetch container, so repeat scans don't re-download. Only npm
# and uv write to them (no package code runs during a fetch). Remove with `docker volume rm`.
NPM_CACHE_VOLUME = "mcpscan-npm-cache"
UV_CACHE_VOLUME = "mcpscan-uv-cache"

# Applied to every sandboxed server container.
RUN_RESTRICTIONS = (
    "--rm", "-i",
    "--network", "none",
    "--read-only", "--tmpfs", "/tmp:rw,exec,size=256m",
    "--cap-drop", "ALL",
    "--security-opt", "no-new-privileges",
    "--pids-limit", "256", "--memory", "1g", "--cpus", "1",
    "-e", "HOME=/tmp",
)  # fmt: skip
FETCH_RESTRICTIONS = ("--rm", "--cap-drop", "ALL", "--security-opt", "no-new-privileges")
NON_ROOT = ("--user", "1000:1000")

# Runs in the fetch container: install without scripts, then print the package's bin path.
_NPM_FETCH = (
    'npm install --prefix /work --ignore-scripts --no-audit --no-fund --loglevel=error "$1" >&2 '
    '&& node -e "$MCPSCAN_BIN_JS" "$2" "$3"'
)
_NPM_BIN_JS = (
    "const [name, want] = process.argv.slice(1);"
    "const pkg = require(`/work/node_modules/${name}/package.json`);"
    "let bin = pkg.bin;"
    "if (bin && typeof bin === 'object') "
    "bin = bin[want] || bin[name.split('/').pop()] || Object.values(bin)[0];"
    "process.stdout.write(`MCPSCAN_BIN=${bin || pkg.main || 'index.js'}\\n`);"
    "process.stdout.write(`MCPSCAN_VERSION=${pkg.version}\\n`);"
)
_PYPI_FETCH = (
    "uv venv -q /work/venv && "
    'uv pip install -q --python /work/venv/bin/python --only-binary :all: "$1" && '
    '/work/venv/bin/python -c "$MCPSCAN_VERSION_PY" "$2"'
)
_PYPI_VERSION_PY = (
    "import sys, importlib.metadata as m; print('MCPSCAN_VERSION=' + m.version(sys.argv[1]))"
)
# ${VAR} / ${env:VAR} (most clients), {env:VAR} (opencode), $VAR; anything else in ${...} is
# client-only (VS Code ${input:...}, Continue ${{ secrets.X }}) and can't be resolved here.
_PLACEHOLDER = re.compile(
    r"\$\{(?:env:)?([A-Za-z_]\w*)\}|\{env:([A-Za-z_]\w*)\}|\$([A-Za-z_]\w*)|\$\{[^}]*\}"
)
_SAFE_NAME = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._-]*$")


class SandboxError(Exception):
    pass


async def _no_cleanup() -> None:
    return None


@dataclass
class Prepared:
    connect: Callable[[], Transport]  # a fresh transport per attempt (handshake fallback)
    label: str  # how the server is being run, for progress output
    cleanup: Callable[[], Awaitable[None]] = _no_cleanup
    remote: bool = False
    sent_credentials: bool = False
    command: list[str] | None = None  # the full command line, for stdio servers
    resolved: PackageMeta | None = None  # the package version / image digest actually run
    # HTTP statuses a remote server answered with (the SDK reports 401s as a generic error).
    http_statuses: list[int] = field(default_factory=list[int])


# --- credentials ----------------------------------------------------------------------------------


def expand(value: str, environ: Mapping[str, str]) -> str | None:
    """Resolve ${VAR}, ${env:VAR} and $VAR the way clients do. None if any can't be resolved
    (including client-only forms like VS Code's ${input:...})."""
    missing = False

    def sub(m: re.Match[str]) -> str:
        nonlocal missing
        name = next((g for g in m.groups() if g), None)
        if name is None or name not in environ:
            missing = True
            return ""
        return environ[name]

    expanded = _PLACEHOLDER.sub(sub, value)
    return None if missing else expanded


def server_env(launch: Launch, *, real_credentials: bool, environ: Mapping[str, str]
               ) -> dict[str, str]:  # fmt: skip
    """The env the server is started with: fake values unless real credentials were asked for."""
    if not real_credentials:
        return dict.fromkeys(launch.env, DUMMY_VALUE)
    out: dict[str, str] = {}
    for key, secret in launch.env.items():
        value = expand(secret.get_secret_value(), environ)
        out[key] = DUMMY_VALUE if value is None else value
    return out


def remote_headers(launch: Launch, *, real_credentials: bool, environ: Mapping[str, str]
                   ) -> dict[str, str]:  # fmt: skip
    if not real_credentials:
        return {}
    headers: dict[str, str] = {}
    for key, secret in launch.headers.items():
        value = expand(secret.get_secret_value(), environ)
        if value is not None:
            headers[key] = value
    return headers


# --- docker ---------------------------------------------------------------------------------------


async def _docker(*args: str, timeout: float) -> str:
    try:
        with anyio.fail_after(timeout):
            done = await anyio.run_process(["docker", *args], check=False)
    except FileNotFoundError as exc:
        raise SandboxError("docker is not installed (or use --sandbox none)") from exc
    except TimeoutError as exc:
        raise SandboxError(f"docker {args[0]} took longer than {timeout:.0f}s") from exc
    if done.returncode != 0:
        detail = done.stderr.decode(errors="replace").strip()[-400:]
        raise SandboxError(f"docker {args[0]} failed: {detail}")
    return done.stdout.decode(errors="replace")


async def docker_available() -> None:
    try:
        await _docker("version", "--format", "{{.Server.Version}}", timeout=20)
    except SandboxError as exc:
        raise SandboxError(
            "the Docker sandbox needs a running Docker daemon (start Docker Desktop), or pass "
            f"--sandbox none to run servers directly on this machine. ({exc})"
        ) from exc


def _env_flags(env: Mapping[str, str]) -> list[str]:
    return [flag for key, value in env.items() for flag in ("-e", f"{key}={value}")]


def npm_bin_path(name: str, bin_relative: str) -> str:
    """Absolute bin path inside the volume; refuses paths that escape the package directory."""
    root = posixpath.join("/work/node_modules", name)
    path = posixpath.normpath(posixpath.join(root, bin_relative))
    if not path.startswith(root + "/"):
        raise SandboxError(f"package {name} declares a bin outside itself: {bin_relative!r}")
    return path


def pypi_requirement(ref: PackageRef) -> str:
    if ref.spec is None:
        return ref.name
    return ref.name + ("==" + ref.spec[1:] if ref.spec.startswith("@") else ref.spec)


def _marker(output: str, prefix: str) -> str | None:
    values = [ln[len(prefix) :].strip() for ln in output.splitlines() if ln.startswith(prefix)]
    return values[-1] if values and values[-1] else None


def _repo_digest(inspect_json: str, name: str) -> str | None:
    """The sha256 digest for `name` from `docker image inspect` RepoDigests output."""
    try:
        data: Any = json.loads(inspect_json or "null")
    except ValueError:
        return None
    digests = cast(list[Any], data) if isinstance(data, list) else []
    for item in digests:
        repo, _, digest = str(item).partition("@")
        if digest and (repo == name or repo.endswith("/" + name)):
            return digest
    return None


async def _prepare_docker(launch: Launch, env: dict[str, str], errlog: TextIO) -> Prepared:
    ref = package_ref(launch)
    if ref is None:
        argv = " ".join(command_line(launch))
        raise SandboxError(
            f"can't sandbox `{argv}`: it doesn't launch a registry package or image. Use "
            "--sandbox none to run it directly on this machine."
        )
    await docker_available()
    argv = command_line(launch)
    server_args = argv[ref.rest_index :]
    tag = uuid.uuid4().hex[:12]
    container, volume = f"mcpscan-run-{tag}", f"mcpscan-pkg-{tag}"

    attempts: list[str] = []  # container names used, one per connection attempt

    async def cleanup() -> None:
        with anyio.CancelScope(shield=True):
            removals = [("rm", "-f", name) for name in attempts] + [("volume", "rm", "-f", volume)]
            for args in removals:
                with contextlib.suppress(SandboxError):
                    await _docker(*args, timeout=30)

    run = ["run", *RUN_RESTRICTIONS, "--name", container, *_env_flags(env)]
    try:
        if ref.registry == "docker":
            image = argv[ref.argv_index]
            await _docker("pull", image, timeout=PULL_TIMEOUT)
            digests = await _docker("image", "inspect", "--format", "{{json .RepoDigests}}",
                                    image, timeout=30)  # fmt: skip
            resolved = PackageMeta(registry="docker", name=ref.name,
                                   version=_repo_digest(digests, ref.name))  # fmt: skip
            config_run = docker_run(launch)
            forwarded = {
                (value or "").split("=", 1)[0]
                for flag, value in (config_run.options if config_run else [])
                if flag in ("-e", "--env") and value
            }
            run = [*run, *_env_flags(dict.fromkeys(forwarded - env.keys(), DUMMY_VALUE))]
            command = [*run, argv[ref.argv_index], *server_args]
            label = f"docker sandbox (image {ref.display}, no network)"
        else:
            await _docker("volume", "create", volume, timeout=30)
            fetch = ["run", *FETCH_RESTRICTIONS, "-v", f"{volume}:/work", "--entrypoint", "sh"]
            mount = ["-v", f"{volume}:/work:ro", *NON_ROOT]
            if ref.registry == "npm":
                spec = f"{ref.name}@{ref.spec}" if ref.spec else ref.name
                bin_js = f"MCPSCAN_BIN_JS={_NPM_BIN_JS}"
                npm_args = ["-v", f"{NPM_CACHE_VOLUME}:/cache", "-e", "npm_config_cache=/cache/npm",
                            "-e", bin_js, NODE_IMAGE, "-c"]  # fmt: skip
                script_args = [_NPM_FETCH, "sh", spec, ref.name, ref.entry or ""]
                output = await _docker(*fetch, *npm_args, *script_args, timeout=FETCH_TIMEOUT)
                found = [ln[len("MCPSCAN_BIN=") :] for ln in output.splitlines()
                         if ln.startswith("MCPSCAN_BIN=")]  # fmt: skip
                if not found:
                    raise SandboxError(f"installed {spec} but couldn't find its executable")
                entry = npm_bin_path(ref.name, found[-1])
                resolved = PackageMeta(registry="npm", name=ref.name,
                                       version=_marker(output, "MCPSCAN_VERSION="))  # fmt: skip
                command = [*run, *mount, "--entrypoint", "node", NODE_IMAGE, entry, *server_args]
            else:
                requirement = pypi_requirement(ref)
                version_py = f"MCPSCAN_VERSION_PY={_PYPI_VERSION_PY}"
                uv_args = ["-v", f"{UV_CACHE_VOLUME}:/cache", "-e", "UV_CACHE_DIR=/cache/uv",
                           "-e", "UV_LINK_MODE=copy", "-e", version_py, UV_IMAGE, "-c"]  # fmt: skip
                output = await _docker(*fetch, *uv_args, _PYPI_FETCH, "sh", requirement, ref.name,
                                       timeout=FETCH_TIMEOUT)  # fmt: skip
                resolved = PackageMeta(registry="pypi", name=ref.name,
                                       version=_marker(output, "MCPSCAN_VERSION="))  # fmt: skip
                entry_name = ref.entry or ref.name
                if not _SAFE_NAME.match(entry_name):
                    raise SandboxError(f"unexpected executable name {entry_name!r}")
                entry = f"/work/venv/bin/{entry_name}"
                command = [*run, *mount, "--entrypoint", entry, UV_IMAGE, *server_args]
            label = f"docker sandbox ({ref.registry} {ref.display}, no network)"
    except BaseException:
        await cleanup()
        raise

    def connect() -> Transport:
        name = f"{container}-{len(attempts)}"
        attempts.append(name)
        args = [name if arg == container else arg for arg in command]
        params = StdioServerParameters(command="docker", args=args, env=get_default_environment())
        return stdio_client(params, errlog=errlog)

    return Prepared(connect, label, cleanup, command=["docker", *command], resolved=resolved)


# --- entry point ----------------------------------------------------------------------------------


async def prepare(
    launch: Launch,
    *,
    sandbox: Sandbox,
    real_credentials: bool,
    errlog: TextIO,
    environ: Mapping[str, str] | None = None,
    extra_headers: Mapping[str, str] | None = None,
    oauth_open: OpenUrl | None = None,
) -> Prepared:
    """`extra_headers`: sent to a remote server as given (--header). `oauth_open`: sign in with
    OAuth, calling it with the authorization URL (--oauth)."""
    environ = os.environ if environ is None else environ
    if launch.transport != "stdio":
        if not launch.url:
            raise SandboxError("remote server has no url")
        headers = remote_headers(launch, real_credentials=real_credentials, environ=environ)
        headers.update(extra_headers or {})
        callback = LoopbackCallback() if oauth_open else None
        auth = oauth_provider(launch.url, callback, oauth_open) if callback and oauth_open else None
        sent = bool(headers) or auth is not None
        label = "remote, " + ("signing in with OAuth" if auth else
                              "credentials sent" if headers else "no credentials sent")  # fmt: skip

        async def cleanup() -> None:
            if callback:
                callback.close()

        if launch.transport == "sse":
            url = launch.url
            return Prepared(lambda: sse_client(url, headers=headers, auth=auth), label, cleanup,
                            remote=True, sent_credentials=sent)  # fmt: skip
        statuses: list[int] = []

        async def record(response: httpx2.Response) -> None:
            statuses.append(response.status_code)

        # MCP's default HTTP timeouts: 30s, and 300s reads for long-lived streams.
        http = httpx2.AsyncClient(headers=headers, auth=auth, event_hooks={"response": [record]},
                                  timeout=httpx2.Timeout(30.0, read=300.0))  # fmt: skip

        async def close_http() -> None:
            await http.aclose()
            await cleanup()

        url = launch.url
        return Prepared(lambda: streamable_http_client(url, http_client=http), label, close_http,
                        remote=True, sent_credentials=sent, http_statuses=statuses)  # fmt: skip

    if not launch.command:
        raise SandboxError("stdio server has no command")
    env = server_env(launch, real_credentials=real_credentials, environ=environ)
    if sandbox == "docker":
        return await _prepare_docker(launch, env, errlog)
    params = StdioServerParameters(
        command=launch.command, args=launch.args, env={**get_default_environment(), **env}
    )
    return Prepared(lambda: stdio_client(params, errlog=errlog), "on this machine, no sandbox",
                    command=[launch.command, *launch.args])  # fmt: skip

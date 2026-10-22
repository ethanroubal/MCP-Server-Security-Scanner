"""Turn what the user typed after `mcpiranha scan` into snapshots."""

from __future__ import annotations

from dataclasses import dataclass, field
from pathlib import Path
from urllib.parse import urlsplit

from pydantic import ValidationError

from mcpiranha.core.io import looks_like_snapshots, parse_snapshots
from mcpiranha.core.models import Launch, Origin, ServerSnapshot
from mcpiranha.discovery import ConfigFile, discover, discover_project, load_config
from mcpiranha.discovery.jsonc import loads

_NEEDS_CONNECT = ("http://", "https://", "npm:", "pypi:", "docker:")


class TargetError(Exception):
    pass


@dataclass
class Targets:
    snapshots: list[ServerSnapshot] = field(default_factory=list[ServerSnapshot])
    config_files: list[ConfigFile] = field(default_factory=list[ConfigFile])
    snapshot_file: Path | None = None
    warnings: list[str] = field(default_factory=list[str])


def package_target(target: str) -> ServerSnapshot:
    """A snapshot for `npm:pkg@1.2.3`, `pypi:pkg==1.2.3`, `docker:image` or a server URL, launched
    the way a client config usually would."""
    if target.startswith(("http://", "https://")):
        parts = urlsplit(target)
        transport = "sse" if parts.path.rstrip("/").endswith("/sse") else "http"
        safe = (
            f"{parts.scheme}://{parts.hostname}{f':{parts.port}' if parts.port else ''}{parts.path}"
        )
        launch = Launch(transport=transport, url=target)
        kind, name, ref = "remote", parts.hostname or target, safe  # no userinfo or query in ids
    else:
        prefix, _, spec = target.partition(":")
        if not spec:
            raise TargetError(f"{target!r}: nothing after {prefix}:")
        if prefix == "npm":
            launch = Launch(transport="stdio", command="npx", args=["-y", spec])
        elif prefix == "pypi":
            launch = Launch(transport="stdio", command="uvx", args=[spec])
        else:
            launch = Launch(transport="stdio", command="docker", args=["run", "-i", "--rm", spec])
        kind, name, ref = prefix, spec, target
    return ServerSnapshot(
        id=f"target:{ref}",
        name=name,
        origin=Origin(kind=kind, ref=ref),  # pyright: ignore[reportArgumentType]
        launch=launch,
        tools_listed=False,
    )


def resolve(target: str | None, cwd: Path, *, connect: bool = False) -> Targets:
    """No target: every known client config plus project configs in `cwd`. A directory: its
    project configs. A file: a client config or a snapshot file, detected from its contents.
    With `connect`, also a package (npm:, pypi:, docker:) or a server URL."""
    if target is None:
        found = discover(project=cwd)
        return Targets(found.snapshots, found.files, warnings=found.errors)
    if target.startswith(_NEEDS_CONNECT):
        if not connect:
            raise TargetError(f"scanning {target!r} means connecting to it: add --connect")
        return Targets([package_target(target)])

    path = Path(target).expanduser()
    if path.is_dir():
        found = discover_project(path)
        return Targets(found.snapshots, found.files, warnings=found.errors)
    if not path.is_file():
        raise TargetError(f"{target} does not exist")

    try:
        data = loads(path.read_text(encoding="utf-8"))
    except (OSError, ValueError) as exc:
        raise TargetError(f"{path} is not readable JSON: {exc}") from exc
    if looks_like_snapshots(data):
        try:
            return Targets(parse_snapshots(data), snapshot_file=path)
        except ValidationError as exc:
            raise TargetError(f"{path} is not a valid snapshot file:\n{exc}") from exc
    found = load_config(path)
    if not found.files:
        raise TargetError("; ".join(found.errors) or f"{path} is not an MCP config file")
    return Targets(found.snapshots, found.files, warnings=found.errors)

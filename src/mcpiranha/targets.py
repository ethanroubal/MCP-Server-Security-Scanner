"""Turn what the user typed after `mcpiranha scan` into snapshots."""

from __future__ import annotations

from dataclasses import dataclass, field, replace
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


def select(
    targets: Targets, *, servers: list[str] | None = None, clients: list[str] | None = None
) -> Targets:
    """Exact selectors: OR within a selector, AND between client and server selectors.

    Validate every selector before acquisition, so a typo never broadens a scan.
    Names can match several clients; use a stable server ID to disambiguate.
    """
    snapshots = targets.snapshots
    for client in clients or []:
        if not any(s.origin.client == client for s in snapshots):
            raise TargetError(f"no client matches {client!r}")
    if clients:
        snapshots = [s for s in snapshots if s.origin.client in clients]
    for server in servers or []:
        if not any(server in (s.name, s.id) for s in snapshots):
            raise TargetError(f"no server matches {server!r} within the selected clients/target")
    if servers:
        snapshots = [s for s in snapshots if s.name in servers or s.id in servers]
    # Config file counts describe discovery, not selection. Keep only relevant files and
    # update their counts so terminal discovery output agrees with the selected scope.
    files = [
        replace(f, servers=sum(s.origin.config_path == str(f.path) for s in snapshots))
        for f in targets.config_files
        if any(s.origin.config_path == str(f.path) for s in snapshots)
    ]
    return Targets(snapshots, files, targets.snapshot_file, targets.warnings)


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
    """Discover configs, load snapshots, or inspect local/package source without execution.

    Config-less directories fall back to source; path: explicitly chooses source. Docker
    images and remote server URLs require an authorized connection.
    """
    if target is None:
        found = discover(project=cwd)
        return Targets(found.snapshots, found.files, warnings=found.errors)
    if target.startswith("path:"):
        if not target[5:]:
            raise TargetError("path: requires a source file or directory")
        return Targets([source_target(Path(target[5:]).expanduser())])
    if target.startswith(_NEEDS_CONNECT):
        if not connect and not target.startswith(("npm:", "pypi:")):
            raise TargetError(f"scanning {target!r} means connecting to it: add --connect")
        return Targets([package_target(target)])

    path = Path(target).expanduser()
    if path.is_dir():
        found = discover_project(path)
        if not found.files and not found.errors:
            return Targets([source_target(path)])
        return Targets(found.snapshots, found.files, warnings=found.errors)
    if not path.is_file():
        raise TargetError(f"{target} does not exist")
    if path.suffix in (".py", ".js", ".mjs", ".cjs", ".ts", ".mts", ".cts", ".tsx", ".jsx"):
        return Targets([source_target(path)])

    try:
        data = loads(path.read_text(encoding="utf-8"))
    except (OSError, ValueError) as exc:
        raise TargetError(f"{path} is not readable JSON: {exc}") from exc
    if looks_like_snapshots(data):
        try:
            snapshots = parse_snapshots(data)
            snapshots = [
                s.model_copy(
                    update={
                        "coverage": {
                            stage: check.model_copy(
                                update={
                                    "reason": (
                                        check.reason
                                        if check.reason.startswith("Saved evidence: ")
                                        else "Saved evidence: " + check.reason
                                    )
                                }
                            )
                            for stage, check in s.coverage.items()
                        }
                    }
                )
                for s in snapshots
            ]
            return Targets(snapshots, snapshot_file=path)
        except ValidationError as exc:
            raise TargetError(f"{path} is not a valid snapshot file:\n{exc}") from exc
    found = load_config(path)
    if not found.files:
        raise TargetError("; ".join(found.errors) or f"{path} is not an MCP config file")
    return Targets(found.snapshots, found.files, warnings=found.errors)


def source_target(path: Path) -> ServerSnapshot:
    """Local source is data, never an executable launch configuration."""
    path = path.resolve()
    if not path.is_file() and not path.is_dir():
        raise TargetError(f"source path {path} does not exist")
    if path.is_file() and path.suffix not in (
        ".py",
        ".js",
        ".mjs",
        ".cjs",
        ".ts",
        ".mts",
        ".cts",
        ".tsx",
        ".jsx",
    ):
        raise TargetError("source files must be Python, JavaScript or TypeScript")
    return ServerSnapshot(
        id=f"path:{path}",
        name=path.name,
        origin=Origin(kind="path", ref=str(path)),
        tools_listed=False,
    )

"""mcp-lock.json: pinned launch configs and tool definitions, for rug-pull detection (MCP-RP-001).

Meant to be committed next to a project's `.mcp.json`, so it never contains a secret: env and
header values aren't stored at all, and secret-looking arguments and URL parts are replaced by a
hash that still changes when the secret does.
"""

from __future__ import annotations

import json
from collections.abc import Sequence
from datetime import UTC, datetime
from pathlib import Path
from typing import Any, Literal
from urllib.parse import urlsplit, urlunsplit

from mcpiranha import __version__
from mcpiranha.core.hashing import hash_json
from mcpiranha.core.models import Launch, PackageMeta, ServerSnapshot, StrictModel
from mcpiranha.core.secrets import redact_args, redacted

LOCKFILE_NAME = "mcp-lock.json"


class LockedTool(StrictModel):
    sha256: str
    definition: dict[str, Any]  # the tool as the server sent it, so changes can be shown as a diff


class LockedServer(StrictModel):
    name: str
    client: str | None = None
    launch: dict[str, Any] | None = None  # see launch_fingerprint()
    launch_sha256: str | None = None
    tools: dict[str, LockedTool] | None = None  # None = tools weren't listed when locking
    manifest_sha256: str | None = None
    # What --connect actually installed: catches `npx -y pkg` silently moving to a new release.
    package: PackageMeta | None = None


class Lockfile(StrictModel):
    lockfile_version: Literal[1] = 1
    generated_by: str
    generated_at: datetime
    servers: dict[str, LockedServer]  # keyed by ServerSnapshot.id

    @classmethod
    def load(cls, path: Path) -> Lockfile:
        return cls.model_validate_json(path.read_text(encoding="utf-8"))

    def save(self, path: Path) -> None:
        data = self.model_dump(mode="json")
        path.write_text(json.dumps(data, indent=2, ensure_ascii=True) + "\n", encoding="utf-8")


def launch_fingerprint(launch: Launch) -> dict[str, Any]:
    """What identifies a launch config, without any secret in it."""
    fingerprint: dict[str, Any] = {"transport": launch.transport}
    if launch.command is not None:
        fingerprint["command"] = launch.command
        fingerprint["args"] = redact_args(launch.args)
    if launch.url is not None:
        parts = urlsplit(launch.url)
        host = parts.hostname or ""
        netloc = f"{host}:{parts.port}" if parts.port else host
        fingerprint["url"] = urlunsplit((parts.scheme, netloc, parts.path, "", ""))
        if parts.query or parts.username or parts.password:
            fingerprint["url_secret_parts"] = redacted(launch.url)
    if launch.env:
        fingerprint["env_names"] = sorted(launch.env)
    if launch.headers:
        fingerprint["header_names"] = sorted(launch.headers)
    return fingerprint


def lock_server(snapshot: ServerSnapshot) -> LockedServer:
    package = snapshot.package
    if package is not None:  # what ran, not what the registry said about it today
        package = PackageMeta(registry=package.registry, name=package.name, version=package.version)
    locked = LockedServer(name=snapshot.name, client=snapshot.origin.client, package=package)
    if snapshot.launch is not None:
        locked.launch = launch_fingerprint(snapshot.launch)
        locked.launch_sha256 = hash_json(locked.launch)
    if snapshot.tools_listed:
        hashes = snapshot.hashes()
        locked.tools = {
            t.name: LockedTool(sha256=hashes.tools[t.name], definition=t.wire_dump())
            for t in snapshot.tools
        }
        locked.manifest_sha256 = hashes.manifest
    return locked


def build_lockfile(snapshots: Sequence[ServerSnapshot]) -> Lockfile:
    return Lockfile(
        generated_by=f"mcpiranha {__version__}",
        generated_at=datetime.now(UTC),
        servers={s.id: lock_server(s) for s in snapshots},
    )

"""Find MCP servers in client config files and turn each entry into a `ServerSnapshot`.

Discovery only reads files. Nothing is launched, so the snapshots have `tools_listed=False`.
"""

from __future__ import annotations

import os
import sys
import tomllib
from collections.abc import Iterator
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, cast

import yaml
from pydantic import SecretStr

from mcpscan.core.models import ClientSettings, Launch, Origin, ServerSnapshot
from mcpscan.discovery.clients import (
    CLIENTS,
    Client,
    Env,
    client_for_file,
    mcp_servers,
    vscode_servers,
)
from mcpscan.discovery.jsonc import loads

_HTTP_TYPES = frozenset({"http", "streamable-http", "streamablehttp", "streamable_http", "remote"})


@dataclass(frozen=True, slots=True)
class ConfigFile:
    client: str
    scope: str  # "user" or "project"
    path: Path
    servers: int


@dataclass
class DiscoveryResult:
    snapshots: list[ServerSnapshot] = field(default_factory=list[ServerSnapshot])
    files: list[ConfigFile] = field(default_factory=list[ConfigFile])
    errors: list[str] = field(default_factory=list[str])

    def extend(self, other: DiscoveryResult) -> None:
        self.snapshots += other.snapshots
        self.files += other.files
        self.errors += other.errors


def current_env() -> Env:
    appdata = os.environ.get("APPDATA")
    return Env(home=Path.home(), platform=sys.platform, appdata=Path(appdata) if appdata else None)


def _strings(value: Any) -> dict[str, SecretStr]:
    if not isinstance(value, dict):
        return {}
    return {str(k): SecretStr(str(v)) for k, v in cast(dict[str, Any], value).items()}


def _str_list(value: Any) -> list[str]:
    return [str(v) for v in cast(list[Any], value)] if isinstance(value, list) else []


def to_launch(entry: dict[str, Any]) -> Launch | None:
    """Normalize one client config entry. Clients disagree on key names; this accepts them all."""
    kind = str(entry.get("type") or entry.get("transport") or "").lower()
    url = entry.get("url") or entry.get("serverUrl") or entry.get("httpUrl")
    command = entry.get("command")
    env, headers = _strings(entry.get("env")), _strings(entry.get("headers"))
    if isinstance(url, str) and (kind in _HTTP_TYPES or kind == "sse" or not command):
        # Entries without a type (Cursor, Windsurf) use the URL: legacy SSE endpoints end in /sse.
        is_sse = kind == "sse" or (not kind and url.split("?")[0].rstrip("/").endswith("/sse"))
        transport = "sse" if is_sse else "http"
        return Launch(transport=transport, url=url, env=env, headers=headers)
    if isinstance(command, str):
        return Launch(transport="stdio", command=command, args=_str_list(entry.get("args")),
                      env=env, headers=headers)  # fmt: skip
    return None


def client_settings(entry: dict[str, Any]) -> ClientSettings | None:
    """The security-relevant flags, whatever each client calls them."""
    approve = _str_list(entry.get("autoApprove") or entry.get("alwaysAllow"))
    settings = ClientSettings(
        disabled=entry.get("disabled") is True or entry.get("enabled") is False,
        auto_approve=[a for a in approve if a != "*"],
        auto_approve_all="*" in approve or entry.get("trust") is True,  # Gemini CLI "trust"
        disabled_tools=_str_list(
            entry.get("disabledTools") or entry.get("disabled_tools") or entry.get("excludeTools")
        ),
    )
    return None if settings == ClientSettings() else settings


def _scope_label(scope: str) -> str:
    return "local" if scope.startswith("local:") else scope


def _parse(path: Path) -> Any:
    text = path.read_text(encoding="utf-8")
    if path.suffix == ".toml":
        return tomllib.loads(text)
    if path.suffix in (".yaml", ".yml"):
        return yaml.safe_load(text)
    return loads(text)


def _read(path: Path, client: Client | None, scope: str) -> DiscoveryResult:
    result = DiscoveryResult()
    try:
        data = _parse(path)
    except (OSError, ValueError, yaml.YAMLError) as exc:
        result.errors.append(f"could not read {path}: {exc}")
        return result
    if not isinstance(data, dict):
        result.errors.append(f"{path}: expected a mapping at the top level")
        return result
    data = cast(dict[str, Any], data)

    client_id = client.id if client else "generic"
    if client is not None:
        entries = client.extract(data, scope)
    elif "mcpServers" in data:  # unknown file: accept either common shape
        entries = mcp_servers(data, scope)
    elif "servers" in data or "mcp" in data:
        entries = vscode_servers(data, scope)
    else:
        result.errors.append(f'{path}: no "mcpServers" or "servers" section')
        return result

    count = 0
    for entry_scope, name, raw in entries:
        entry = client.normalize(raw) if client else raw
        if entry is None:
            continue  # not an MCP server (e.g. a Goose builtin)
        launch = to_launch(entry)
        if launch is None:
            result.errors.append(f"{path}: server {name!r} has neither a command nor a url")
            continue
        count += 1
        result.snapshots.append(
            ServerSnapshot(
                id=f"{client_id}:{entry_scope}:{name}",
                name=name,
                origin=Origin(kind="config", client=client_id, config_path=str(path), ref=name),
                launch=launch,
                client_settings=client_settings(entry),
                tools_listed=False,
            )
        )
    result.files.append(ConfigFile(client_id, _scope_label(scope), path, count))
    return result


def load_config(path: Path) -> DiscoveryResult:
    """Read one config file, guessing the client from its name and location."""
    client = client_for_file(path)
    in_project = client is not None and client.matches_project_path(path)
    return _read(path, client, "project" if in_project else "user")


def _project_files(client: Client, directory: Path) -> Iterator[Path]:
    for relative in client.project_paths:
        if "*" in relative:
            yield from sorted(directory.glob(relative))
        else:
            yield directory / relative


def discover_project(directory: Path) -> DiscoveryResult:
    return discover(env=None, project=directory, user=False)


def discover(env: Env | None = None, project: Path | None = None, *, user: bool = True
             ) -> DiscoveryResult:  # fmt: skip
    """Every user-level config for every known client, plus project configs in `project`."""
    env = env or current_env()
    result = DiscoveryResult()
    seen: set[Path] = set()
    candidates: list[tuple[Client, Path, str]] = []
    if user:
        candidates += [(c, path, "user") for c in CLIENTS for path in c.user_paths(env)]
    if project is not None:
        candidates += [(c, path, "project") for c in CLIENTS for path in _project_files(c, project)]
    for client, path, scope in candidates:
        if path.is_file() and (resolved := path.resolve()) not in seen:
            seen.add(resolved)  # e.g. ~/.cursor/mcp.json when the project is the home directory
            result.extend(_read(path, client, scope))
    return result

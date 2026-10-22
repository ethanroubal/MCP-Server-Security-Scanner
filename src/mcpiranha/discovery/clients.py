"""Where each MCP client keeps its config, and how to read the server entries out of it.

Adding a client: write one `Client` entry. `extract` finds the server entries in the parsed file;
`normalize` rewrites one entry into the common shape `to_launch` understands (command / args /
env, or url / type / headers). Paths are resolved against an explicit home directory and
platform so tests can build a fake one. Files are parsed by extension: .toml, .yaml/.yml, or
JSON with comments.

Formats were checked against each client's documentation in October 2026; see
docs/CLIENTS.md for sources and the paths that docs didn't confirm.
"""

from __future__ import annotations

from collections.abc import Callable, Iterator, Mapping
from dataclasses import dataclass, field
from pathlib import Path, PurePosixPath
from typing import Any, cast

Entries = Iterator[tuple[str, str, dict[str, Any]]]  # (scope, server name, raw entry)
Normalize = Callable[[dict[str, Any]], dict[str, Any] | None]  # None = not a server; skip it

# Editors built on VS Code, whose extensions (Cline, Roo Code) keep settings in globalStorage.
VSCODE_FAMILY = ("Code", "Code - Insiders", "Cursor", "Windsurf", "VSCodium")


@dataclass(frozen=True, slots=True)
class Env:
    home: Path
    platform: str  # sys.platform value: "darwin", "linux", "win32"
    appdata: Path | None = None  # %APPDATA% on Windows

    def app_support(self, *parts: str) -> Path:
        """The per-user application data directory for this platform."""
        if self.platform == "darwin":
            return self.home.joinpath("Library", "Application Support", *parts)
        if self.platform == "win32":
            return self.roaming.joinpath(*parts)
        return self.home.joinpath(".config", *parts)

    @property
    def roaming(self) -> Path:
        return self.appdata or self.home / "AppData" / "Roaming"

    def xdg_config(self, *parts: str) -> Path:
        """~/.config on every platform (where Zed, Goose and opencode look on macOS too)."""
        return self.home.joinpath(".config", *parts)


# --- extracting entries ---------------------------------------------------------------------------


def _servers(value: Any) -> Iterator[tuple[str, dict[str, Any]]]:
    if isinstance(value, dict):
        for name, entry in cast(dict[str, Any], value).items():
            if isinstance(entry, dict):
                yield str(name), cast(dict[str, Any], entry)


def keyed(key: str) -> Callable[[dict[str, Any], str], Entries]:
    """Extractor for a map of name -> entry under `key`."""

    def extract(data: dict[str, Any], scope: str) -> Entries:
        for name, entry in _servers(data.get(key)):
            yield scope, name, entry

    return extract


mcp_servers = keyed("mcpServers")


def claude_code_servers(data: dict[str, Any], scope: str) -> Entries:
    """~/.claude.json holds user-scope servers at the top and local-scope ones per project."""
    yield from mcp_servers(data, scope)
    projects = data.get("projects")
    if isinstance(projects, dict):
        for project, settings in cast(dict[str, Any], projects).items():
            if isinstance(settings, dict):
                yield from mcp_servers(cast(dict[str, Any], settings), f"local:{project}")


def vscode_servers(data: dict[str, Any], scope: str) -> Entries:
    """mcp.json has top-level "servers"; older settings.json nests it under "mcp"."""
    mcp = data.get("mcp")
    nested = cast(dict[str, Any], mcp).get("servers") if isinstance(mcp, dict) else None
    for name, entry in _servers(data.get("servers") or nested):
        yield scope, name, entry


def continue_servers(data: dict[str, Any], scope: str) -> Entries:
    """Continue lists servers (`- name: ...`); JSON files in .continue/mcpServers use a map."""
    servers = data.get("mcpServers")
    if isinstance(servers, list):
        for item in cast(list[Any], servers):
            if not isinstance(item, dict):
                continue
            entry = cast(dict[str, Any], item)
            if isinstance(name := entry.get("name"), str):
                yield scope, name, entry
    else:
        yield from mcp_servers(data, scope)


# --- normalizing entries --------------------------------------------------------------------------


def _same(entry: dict[str, Any]) -> dict[str, Any]:
    return entry


def _zed(entry: dict[str, Any]) -> dict[str, Any]:
    """Older Zed settings nest the command: {"command": {"path", "args", "env"}}."""
    command = entry.get("command")
    if isinstance(command, dict):
        nested = cast(dict[str, Any], command)
        return {**entry, "command": nested.get("path"), "args": nested.get("args", []),
                "env": nested.get("env", {})}  # fmt: skip
    return entry


def _cline(entry: dict[str, Any]) -> dict[str, Any]:
    """A Cline URL entry without a type is SSE."""
    return {**entry, "type": "sse"} if entry.get("url") and not entry.get("type") else entry


def _gemini(entry: dict[str, Any]) -> dict[str, Any]:
    """Gemini CLI picks the transport by key: `httpUrl` is streamable HTTP, `url` is SSE."""
    if entry.get("httpUrl"):
        return {**entry, "url": entry["httpUrl"], "type": "http"}
    return {**entry, "type": "sse"} if entry.get("url") else entry


def _codex(entry: dict[str, Any]) -> dict[str, Any]:
    """Codex names env vars for headers rather than storing values; keep them as ${VAR}."""
    headers: dict[str, Any] = dict(cast(dict[str, Any], entry.get("http_headers") or {}))
    for header, var in cast(dict[str, Any], entry.get("env_http_headers") or {}).items():
        headers[header] = f"${{{var}}}"
    if var := entry.get("bearer_token_env_var"):
        headers["Authorization"] = f"Bearer ${{{var}}}"
    return {**entry, "headers": headers, "type": "http" if entry.get("url") else "stdio"}


def _goose(entry: dict[str, Any]) -> dict[str, Any] | None:
    kind = entry.get("type")
    if kind not in ("stdio", "sse", "streamable_http"):
        return None  # builtin / platform extensions run inside Goose itself
    return {**entry, "command": entry.get("cmd"), "env": entry.get("envs") or {},
            "url": entry.get("uri")}  # fmt: skip


def _opencode(entry: dict[str, Any]) -> dict[str, Any] | None:
    """opencode: {"type": "local", "command": [argv...], "environment": {...}} or remote."""
    if entry.get("type") == "remote":
        return {**entry, "type": "http"}
    command = entry.get("command")
    if not isinstance(command, list) or not command:
        return None
    argv = [str(a) for a in cast(list[Any], command)]
    return {**entry, "type": "stdio", "command": argv[0], "args": argv[1:],
            "env": entry.get("environment") or {}}  # fmt: skip


# --- the clients ----------------------------------------------------------------------------------


@dataclass(frozen=True, slots=True)
class Client:
    id: str
    display: str
    user_paths: Callable[[Env], list[Path]]
    project_paths: tuple[str, ...]  # relative to a project directory; may contain * globs
    extract: Callable[[dict[str, Any], str], Entries] = mcp_servers
    normalize: Normalize = _same
    filenames: tuple[str, ...] = field(default=())  # for recognizing a file passed directly

    def matches_project_path(self, path: Path) -> bool:
        posix = PurePosixPath(path.as_posix())
        return any(posix.match(f"*/{relative}") or posix.match(relative)
                   for relative in self.project_paths)  # fmt: skip


def _vscode_storage(env: Env, extension: str, filename: str) -> list[Path]:
    return [env.app_support(product, "User", "globalStorage", extension, "settings", filename)
            for product in VSCODE_FAMILY]  # fmt: skip


CLIENTS: tuple[Client, ...] = (
    Client(
        id="claude-desktop",
        display="Claude Desktop",
        user_paths=lambda e: [e.app_support("Claude", "claude_desktop_config.json")],
        project_paths=(),
        filenames=("claude_desktop_config.json",),
    ),
    Client(
        id="claude-code",
        display="Claude Code",
        user_paths=lambda e: [e.home / ".claude.json"],
        project_paths=(".mcp.json",),
        extract=claude_code_servers,
        filenames=(".claude.json", ".mcp.json"),
    ),
    Client(
        id="cursor",
        display="Cursor",
        user_paths=lambda e: [e.home / ".cursor" / "mcp.json"],
        project_paths=(".cursor/mcp.json",),
    ),
    Client(
        id="vscode",
        display="VS Code",
        user_paths=lambda e: [
            e.app_support(product, "User", name)
            for product in ("Code", "Code - Insiders")
            for name in ("mcp.json", "settings.json")
        ],
        project_paths=(".vscode/mcp.json",),
        extract=vscode_servers,
    ),
    Client(
        id="windsurf",
        display="Windsurf",
        user_paths=lambda e: [e.home / ".codeium" / "windsurf" / "mcp_config.json"],
        project_paths=(),
        filenames=("mcp_config.json",),
    ),
    Client(
        id="zed",
        display="Zed",
        user_paths=lambda e: [
            e.roaming / "Zed" / "settings.json"
            if e.platform == "win32"
            else e.xdg_config("zed", "settings.json")
        ],
        project_paths=(".zed/settings.json",),
        extract=keyed("context_servers"),
        normalize=_zed,
    ),
    Client(
        id="cline",
        display="Cline",
        user_paths=lambda e: [
            e.home / ".cline" / "data" / "settings" / "cline_mcp_settings.json",  # Cline CLI
            *_vscode_storage(e, "saoudrizwan.claude-dev", "cline_mcp_settings.json"),
        ],
        project_paths=(),
        normalize=_cline,
        filenames=("cline_mcp_settings.json",),
    ),
    Client(
        id="roo-code",
        display="Roo Code",
        user_paths=lambda e: _vscode_storage(e, "rooveterinaryinc.roo-cline", "mcp_settings.json"),
        project_paths=(".roo/mcp.json",),
        filenames=("mcp_settings.json",),
    ),
    Client(
        id="gemini-cli",
        display="Gemini CLI",
        user_paths=lambda e: [e.home / ".gemini" / "settings.json"],
        project_paths=(".gemini/settings.json",),
        normalize=_gemini,
    ),
    Client(
        id="codex",
        display="Codex CLI",
        user_paths=lambda e: [e.home / ".codex" / "config.toml"],
        project_paths=(".codex/config.toml",),
        extract=keyed("mcp_servers"),
        normalize=_codex,
    ),
    Client(
        id="continue",
        display="Continue",
        user_paths=lambda e: [e.home / ".continue" / "config.yaml"],
        project_paths=(
            ".continue/mcpServers/*.yaml",
            ".continue/mcpServers/*.yml",
            ".continue/mcpServers/*.json",
        ),
        extract=continue_servers,
    ),
    Client(
        id="goose",
        display="Goose",
        user_paths=lambda e: [
            e.xdg_config("goose", "config.yaml"),
            e.roaming / "Block" / "goose" / "config" / "config.yaml",
        ],
        project_paths=(),
        extract=keyed("extensions"),
        normalize=_goose,
    ),
    Client(
        id="amazon-q",
        display="Amazon Q Developer CLI",
        user_paths=lambda e: [e.home / ".aws" / "amazonq" / "mcp.json"],
        project_paths=(".amazonq/mcp.json",),
    ),
    Client(
        id="kiro",
        display="Kiro",
        user_paths=lambda e: [e.home / ".kiro" / "settings" / "mcp.json"],
        project_paths=(".kiro/settings/mcp.json",),
    ),
    Client(
        id="opencode",
        display="opencode",
        user_paths=lambda e: [
            e.xdg_config("opencode", "opencode.json"),
            e.xdg_config("opencode", "opencode.jsonc"),
        ],
        project_paths=("opencode.json", "opencode.jsonc"),
        extract=keyed("mcp"),
        normalize=_opencode,
        filenames=("opencode.json", "opencode.jsonc"),
    ),
    Client(
        id="lm-studio",
        display="LM Studio",
        user_paths=lambda e: [e.home / ".lmstudio" / "mcp.json"],
        project_paths=(),
    ),
)

CLIENTS_BY_ID: Mapping[str, Client] = {c.id: c for c in CLIENTS}


def client_for_file(path: Path) -> Client | None:
    """Guess which client a config file belongs to from its name and location."""
    name, parent = path.name, path.parent.name.lower()
    parts = {p.lower() for p in path.parts}
    checks: tuple[tuple[str, bool], ...] = (
        ("cursor", name == "mcp.json" and ".cursor" in parts),
        ("kiro", name == "mcp.json" and ".kiro" in parts),
        ("amazon-q", name == "mcp.json" and bool({".amazonq", "amazonq"} & parts)),
        ("lm-studio", name == "mcp.json" and ".lmstudio" in parts),
        ("roo-code", (name == "mcp.json" and parent == ".roo") or name == "mcp_settings.json"),
        ("zed", name == "settings.json" and parent in (".zed", "zed")),
        ("gemini-cli", name == "settings.json" and parent == ".gemini"),
        ("codex", path.suffix == ".toml" and parent == ".codex"),
        ("continue", ".continue" in parts),
        ("goose", path.suffix in (".yaml", ".yml") and "goose" in parts),
        ("vscode", name in ("mcp.json", "settings.json") and bool({".vscode", "user"} & parts)),
    )
    for client_id, matched in checks:
        if matched:
            return CLIENTS_BY_ID[client_id]
    for client in CLIENTS:
        if name in client.filenames:
            return client
    return None

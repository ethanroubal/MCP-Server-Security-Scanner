"""Discovery for the clients beyond Claude/Cursor/VS Code/Windsurf, each at its real path."""

from __future__ import annotations

import shutil
from pathlib import Path

import pytest

from mcpiranha.core.models import Launch, ServerSnapshot
from mcpiranha.discovery import discover, load_config
from mcpiranha.discovery.clients import Env

CONFIGS = Path(__file__).parent.parent / "fixtures" / "configs"
CLINE_STORAGE = (
    "Library/Application Support/Code/User/globalStorage/saoudrizwan.claude-dev/settings"
)

HOME_LAYOUT = {
    ".config/zed/settings.json": "zed.settings.json",
    f"{CLINE_STORAGE}/cline_mcp_settings.json": "cline_mcp_settings.json",
    ".gemini/settings.json": "gemini.settings.json",
    ".codex/config.toml": "codex.config.toml",
    ".continue/config.yaml": "continue.config.yaml",
    ".config/goose/config.yaml": "goose.config.yaml",
    ".aws/amazonq/mcp.json": "amazonq.mcp.json",
    ".kiro/settings/mcp.json": "kiro.mcp.json",
    ".config/opencode/opencode.json": "opencode.json",
    ".lmstudio/mcp.json": "lmstudio.mcp.json",
}
PROJECT_LAYOUT = {
    ".roo/mcp.json": "roo.mcp.json",
    ".continue/mcpServers/browser.yaml": "continue.block.yaml",
}


def _install(root: Path, layout: dict[str, str]) -> None:
    for dest, fixture in layout.items():
        target = root / dest
        target.parent.mkdir(parents=True, exist_ok=True)
        shutil.copy(CONFIGS / fixture, target)


@pytest.fixture
def found(tmp_path: Path) -> dict[str, ServerSnapshot]:
    home, project = tmp_path / "home", tmp_path / "project"
    _install(home, HOME_LAYOUT)
    _install(project, PROJECT_LAYOUT)
    result = discover(Env(home=home, platform="darwin"), project=project)
    assert result.errors == []
    return {s.id: s for s in result.snapshots}


def _launch(found: dict[str, ServerSnapshot], sid: str) -> Launch:
    launch = found[sid].launch
    assert launch is not None
    return launch


def test_every_client_is_found(found: dict[str, ServerSnapshot]) -> None:
    assert sorted(found) == sorted([
        "zed:user:postgres", "zed:user:legacy", "zed:user:remote-docs",
        "cline:user:github", "cline:user:legacy-sse", "cline:user:off",
        "gemini-cli:user:local-tools", "gemini-cli:user:events", "gemini-cli:user:api",
        "codex:user:docs", "codex:user:tracker", "codex:user:off",
        "continue:user:SQLite", "continue:user:Remote", "continue:project:Browser",
        "goose:user:github", "goose:user:hosted",  # the builtin "developer" isn't a server
        "amazon-q:user:aws-docs",
        "kiro:user:fetch", "kiro:user:disabled-one",
        "opencode:user:local-db", "opencode:user:remote-kb",
        "lm-studio:user:hf",
        "roo-code:project:files", "roo-code:project:search",
    ])  # fmt: skip


def test_zed_nested_and_flat_commands(found: dict[str, ServerSnapshot]) -> None:
    legacy = _launch(found, "zed:user:legacy")
    assert (legacy.command, legacy.args, list(legacy.env)) == ("uvx", ["mcp-server-time"], ["TZ"])
    assert _launch(found, "zed:user:postgres").command == "npx"
    assert _launch(found, "zed:user:remote-docs").transport == "http"


def test_transport_conventions(found: dict[str, ServerSnapshot]) -> None:
    assert _launch(found, "cline:user:legacy-sse").transport == "sse"  # Cline: url, no type
    assert _launch(found, "gemini-cli:user:events").transport == "sse"  # Gemini: url
    assert _launch(found, "gemini-cli:user:api").transport == "http"  # Gemini: httpUrl
    assert _launch(found, "roo-code:project:search").transport == "http"
    assert _launch(found, "continue:user:Remote").transport == "http"
    assert _launch(found, "goose:user:hosted").url == "https://hosted.example.com/mcp"
    assert _launch(found, "opencode:user:remote-kb").transport == "http"


def test_command_shapes(found: dict[str, ServerSnapshot]) -> None:
    goose = _launch(found, "goose:user:github")  # cmd / envs
    assert goose.command == "npx" and "GITHUB_PERSONAL_ACCESS_TOKEN" in goose.env
    opencode = _launch(found, "opencode:user:local-db")  # command array / environment
    assert (opencode.command, opencode.args) == ("npx", ["-y", "db-mcp@3.0.0", "--readonly"])
    assert opencode.env["DB_URL"].get_secret_value() == "{env:DB_URL}"


def test_codex_header_env_vars_become_placeholders(found: dict[str, ServerSnapshot]) -> None:
    headers = _launch(found, "codex:user:tracker").headers
    assert headers["Authorization"].get_secret_value() == "Bearer ${TRACKER_TOKEN}"
    assert headers["X-Team"].get_secret_value() == "platform"


def test_client_settings(found: dict[str, ServerSnapshot]) -> None:
    def settings(sid: str):
        s = found[sid].client_settings
        assert s is not None, sid
        return s

    assert settings("cline:user:github").auto_approve == ["get_issue", "create_pull_request"]
    assert settings("cline:user:off").disabled
    assert settings("roo-code:project:files").auto_approve == ["read_file"]
    assert settings("roo-code:project:search").disabled_tools == ["delete_index"]
    assert settings("gemini-cli:user:local-tools").auto_approve_all  # "trust": true
    assert settings("kiro:user:fetch").auto_approve_all  # autoApprove: ["*"]
    assert settings("kiro:user:disabled-one").disabled
    assert settings("codex:user:off").disabled  # enabled = false
    assert settings("goose:user:hosted").disabled  # enabled: false
    assert found["amazon-q:user:aws-docs"].client_settings is None


@pytest.mark.parametrize(
    ("dest", "fixture", "client", "scope"),
    [
        (".zed/settings.json", "zed.settings.json", "zed", "project"),
        ("x/.gemini/settings.json", "gemini.settings.json", "gemini-cli", "project"),
        (".codex/config.toml", "codex.config.toml", "codex", "project"),
        (".kiro/settings/mcp.json", "kiro.mcp.json", "kiro", "project"),
        (".roo/mcp.json", "roo.mcp.json", "roo-code", "project"),
        ("opencode.json", "opencode.json", "opencode", "project"),
        ("cfg/cline_mcp_settings.json", "cline_mcp_settings.json", "cline", "user"),
        (".continue/mcpServers/b.yaml", "continue.block.yaml", "continue", "project"),
    ],
)
def test_load_config_detects_new_clients(tmp_path: Path, dest: str, fixture: str, client: str,
                                         scope: str) -> None:  # fmt: skip
    _install(tmp_path, {dest: fixture})
    result = load_config(tmp_path / dest)
    assert result.errors == []
    assert {s.origin.client for s in result.snapshots} == {client}
    assert {s.id.split(":")[1] for s in result.snapshots} == {scope}


def test_placeholders_in_new_formats_are_not_secrets(found: dict[str, ServerSnapshot]) -> None:
    from mcpiranha.core.secrets import classify

    for sid in ("opencode:user:local-db", "codex:user:tracker", "zed:user:remote-docs"):
        launch = _launch(found, sid)
        for name, value in [*launch.env.items(), *launch.headers.items()]:
            assert classify(name, value.get_secret_value()) is None, (sid, name)

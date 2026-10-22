import shutil
from pathlib import Path

from mcpiranha.discovery import discover, load_config
from mcpiranha.discovery.clients import Env
from mcpiranha.discovery.jsonc import loads

CONFIGS = Path(__file__).parent.parent / "fixtures" / "configs"

MACOS_LAYOUT = {
    "Library/Application Support/Claude/claude_desktop_config.json": "claude_desktop_config.json",
    ".claude.json": "claude.json",
    ".cursor/mcp.json": "cursor.mcp.json",
    "Library/Application Support/Code/User/mcp.json": "vscode.mcp.json",
    "Library/Application Support/Code/User/settings.json": "vscode.settings.json",
    ".codeium/windsurf/mcp_config.json": "windsurf.mcp_config.json",
}


def _install(root: Path, layout: dict[str, str]) -> None:
    for dest, fixture in layout.items():
        target = root / dest
        target.parent.mkdir(parents=True, exist_ok=True)
        shutil.copy(CONFIGS / fixture, target)


def test_discovers_every_client(tmp_path: Path) -> None:
    home, project = tmp_path / "home", tmp_path / "project"
    _install(home, MACOS_LAYOUT)
    _install(project, {".mcp.json": "project.mcp.json"})

    result = discover(Env(home=home, platform="darwin"), project=project)

    assert result.errors == []
    assert {s.id for s in result.snapshots} == {
        "claude-desktop:user:filesystem",
        "claude-desktop:user:github",
        "claude-code:user:context7",
        "claude-code:local:/Users/alice/code/webapp:sentry",
        "claude-code:project:postgres",
        "claude-code:project:linear",
        "cursor:user:browser",
        "cursor:user:remote-notes",
        "vscode:user:time",
        "vscode:user:docs",
        "vscode:user:legacy-fetch",
        "windsurf:user:deepwiki",
        "windsurf:user:git",
    }
    assert all(not s.tools_listed for s in result.snapshots)
    assert len(result.files) == 7


def test_entries_are_normalized(tmp_path: Path) -> None:
    home = tmp_path / "home"
    _install(home, MACOS_LAYOUT)
    by_id = {s.id: s for s in discover(Env(home=home, platform="darwin")).snapshots}

    def launch(sid: str):
        result = by_id[sid].launch
        assert result is not None
        return result

    github = launch("claude-desktop:user:github")
    assert github.transport == "stdio"
    assert github.args == ["-y", "@modelcontextprotocol/server-github"]
    assert github.env["GITHUB_PERSONAL_ACCESS_TOKEN"].get_secret_value().startswith("ghp_")
    assert launch("claude-code:local:/Users/alice/code/webapp:sentry").transport == "http"
    assert launch("cursor:user:remote-notes").transport == "http"  # url without a type
    assert launch("windsurf:user:deepwiki").transport == "sse"  # serverUrl ending in /sse
    assert launch("vscode:user:docs").headers["Authorization"].get_secret_value() == (
        "Bearer ${input:api-key}"
    )
    assert by_id["vscode:user:time"].origin.config_path == str(
        home / "Library/Application Support/Code/User/mcp.json"
    )


def test_platform_paths(tmp_path: Path) -> None:
    linux_home = tmp_path / "linux"
    _install(
        linux_home, {".config/Claude/claude_desktop_config.json": "claude_desktop_config.json"}
    )
    assert len(discover(Env(home=linux_home, platform="linux")).snapshots) == 2

    appdata = tmp_path / "AppData" / "Roaming"
    _install(appdata, {"Claude/claude_desktop_config.json": "claude_desktop_config.json"})
    env = Env(home=tmp_path / "winhome", platform="win32", appdata=appdata)
    assert len(discover(env).snapshots) == 2


def test_home_as_project_is_not_read_twice(tmp_path: Path) -> None:
    _install(tmp_path, {".cursor/mcp.json": "cursor.mcp.json"})
    result = discover(Env(home=tmp_path, platform="darwin"), project=tmp_path)
    assert sorted(s.name for s in result.snapshots) == ["browser", "remote-notes"]


def test_unreadable_config_is_reported_not_fatal(tmp_path: Path) -> None:
    _install(tmp_path, {".claude.json": "claude.json"})
    (tmp_path / ".cursor").mkdir()
    (tmp_path / ".cursor" / "mcp.json").write_text("{ not json", encoding="utf-8")
    result = discover(Env(home=tmp_path, platform="darwin"))
    assert len(result.errors) == 1 and "mcp.json" in result.errors[0]
    assert {s.name for s in result.snapshots} == {"context7", "sentry"}


def test_load_config_detects_client_and_scope(tmp_path: Path) -> None:
    _install(tmp_path, {".vscode/mcp.json": "vscode.mcp.json", "x/mcp_config.json":
                        "windsurf.mcp_config.json"})  # fmt: skip
    vscode = load_config(tmp_path / ".vscode" / "mcp.json")
    assert {(s.origin.client, s.id.split(":")[1]) for s in vscode.snapshots} == {
        ("vscode", "project")
    }
    assert load_config(tmp_path / "x" / "mcp_config.json").snapshots[0].origin.client == "windsurf"


def test_jsonc_keeps_strings_intact() -> None:
    text = '{"url": "http://a//b", /* note */ "s": "/* not a comment */", "l": [1, 2,],} // end'
    assert loads(text) == {"url": "http://a//b", "s": "/* not a comment */", "l": [1, 2]}

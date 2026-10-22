# Supported MCP clients

Where `mcpiranha scan` looks, and how each format is read. Formats were checked against each
client's documentation on 2026-10-20. Paths marked **unverified** come from earlier knowledge of
the client and weren't confirmed by its current docs; please report corrections.

`~` is your home directory. "App data" is `~/Library/Application Support` on macOS,
`%APPDATA%` on Windows and `~/.config` on Linux.

| Client | User config | Project config | Format | Notes |
|---|---|---|---|---|
| Claude Desktop | App data `/Claude/claude_desktop_config.json` | — | JSON `mcpServers` | |
| Claude Code | `~/.claude.json` (user, plus per-project "local" scope) | `.mcp.json` | JSON `mcpServers` | |
| Cursor | `~/.cursor/mcp.json` | `.cursor/mcp.json` | JSON `mcpServers` | URL without type: `/sse` path = SSE |
| VS Code | App data `/Code/User/mcp.json`, legacy `settings.json` `mcp.servers` (also Insiders) | `.vscode/mcp.json` | JSONC `servers` | `${input:...}` treated as a placeholder |
| Windsurf | `~/.codeium/windsurf/mcp_config.json` | — | JSON `mcpServers` | `serverUrl` |
| Zed | `~/.config/zed/settings.json` (macOS/Linux, docs summary); Windows `%APPDATA%\Zed\settings.json` **unverified** | `.zed/settings.json` | JSONC `context_servers` | Flat and older nested `command: {path, args, env}` forms |
| Cline | CLI: `~/.cline/data/settings/cline_mcp_settings.json`; extension: VS Code-family `globalStorage/saoudrizwan.claude-dev/settings/cline_mcp_settings.json` **unverified** | — | JSON `mcpServers` | URL without `type` = SSE; `autoApprove`, `disabled` |
| Roo Code | VS Code-family `globalStorage/rooveterinaryinc.roo-cline/settings/mcp_settings.json` **unverified** | `.roo/mcp.json` | JSON `mcpServers` | `alwaysAllow`, `disabled`, `disabledTools`; `${env:VAR}` |
| Gemini CLI | `~/.gemini/settings.json` | `.gemini/settings.json` | JSON `mcpServers` | `url` = SSE, `httpUrl` = streamable HTTP; `trust: true` skips confirmation |
| Codex CLI | `~/.codex/config.toml` | `.codex/config.toml` (trusted projects) | TOML `[mcp_servers.<id>]` | `bearer_token_env_var`, `env_http_headers` → `${VAR}` headers; `enabled = false` |
| Continue | `~/.continue/config.yaml` | `.continue/mcpServers/*.yaml`, `*.yml`, `*.json` | YAML list `mcpServers: - name:` | `${{ secrets.X }}` treated as a placeholder |
| Goose | `~/.config/goose/config.yaml`; Windows `%APPDATA%\Block\goose\config\config.yaml` **unverified** | — | YAML `extensions` | `cmd`/`args`/`envs`, `uri`; `builtin` extensions skipped; `enabled` |
| Amazon Q Developer CLI | `~/.aws/amazonq/mcp.json` | `.amazonq/mcp.json` | JSON `mcpServers` (format **unverified**: docs page unreadable) | |
| Kiro | `~/.kiro/settings/mcp.json` | `.kiro/settings/mcp.json` | JSON `mcpServers` | `autoApprove` (`"*"` = all), `disabled`, `disabledTools` |
| opencode | `~/.config/opencode/opencode.json` / `.jsonc` | `opencode.json` / `.jsonc` | JSONC `mcp` | `type: local` with `command` array and `environment`; `type: remote`; `{env:VAR}` |
| LM Studio | `~/.lmstudio/mcp.json` **unverified** | — | JSON `mcpServers` (Cursor notation) | |

VS Code-family editors searched for Cline and Roo Code storage: Code, Code - Insiders, Cursor,
Windsurf, VSCodium.

## Security-relevant settings

Discovery records these per server, whatever the client calls them, and MCP-CF-006 reports them:

| Setting | Read from |
|---|---|
| Disabled (not started by the client; `--connect` skips it) | `disabled: true`, `enabled: false` |
| Tools run without confirmation | `autoApprove`, `alwaysAllow` |
| Every tool runs without confirmation | `autoApprove: ["*"]`, Gemini `trust: true` |
| Tools turned off | `disabledTools`, `disabled_tools`, `excludeTools` |

## Sources

- Zed: https://zed.dev/docs/ai/mcp, https://zed.dev/docs/reference/all-settings
- Cline: https://docs.cline.bot/mcp/configuring-mcp-servers
- Roo Code: https://roocodeinc.github.io/Roo-Code/features/mcp/using-mcp-in-roo
- Gemini CLI: https://github.com/google-gemini/gemini-cli/blob/main/docs/tools/mcp-server.md
- Codex CLI: https://learn.chatgpt.com/docs/config-file/config-reference (MCP section from a summary)
- Continue: https://docs.continue.dev/customize/deep-dives/mcp
- Goose: https://goose-docs.ai/docs/getting-started/using-extensions
- Amazon Q Developer CLI: paths via https://kiro.dev/docs/upgrade-guides/migrating-from-q/
- Kiro: https://kiro.dev/docs/mcp/configuration/
- opencode: https://opencode.ai/docs/mcp-servers/, https://opencode.ai/docs/config/
- LM Studio: https://lmstudio.ai/docs/app/plugins/mcp

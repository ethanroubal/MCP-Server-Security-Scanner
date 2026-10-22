# mcpscan

Security scanner for Model Context Protocol (MCP) servers: tool poisoning, cross-server shadowing,
rug pulls, insecure configuration, vulnerable implementations and dangerous combinations of servers.
It works fully offline; bringing your own LLM is optional. Design: [docs/ARCHITECTURE.md](docs/ARCHITECTURE.md).

**Status: Phase 1 complete.** 21 rules (see [docs/RULES.md](docs/RULES.md)) run on client
configs, snapshot files and, with `--connect`, on what servers actually serve.

## Usage

```bash
mcpscan scan                      # every MCP client config on this machine + the current project
mcpscan scan .mcp.json            # one config file (Claude, Cursor, VS Code, Windsurf formats)
mcpscan scan ./some-project       # a project's .mcp.json, .cursor/mcp.json, .vscode/mcp.json
mcpscan scan --connect            # also start/reach each server and check its tools, prompts, resources
mcpscan scan --connect npm:@scope/server@1.2.3   # vet a package before installing it
mcpscan scan --connect https://mcp.example.com/mcp --oauth          # sign in (opens a browser)
mcpscan scan --connect https://mcp.example.com/mcp -H "Authorization: Bearer $TOKEN"
mcpscan scan --connect --strict   # CI: exit 2 if any server couldn't be checked
mcpscan scan -f sarif -o mcpscan.sarif   # for GitHub code scanning
mcpscan lock --connect            # pin launch configs and tool definitions to mcp-lock.json
mcpscan verify --connect          # exit 1 if anything changed or was added since the lock
mcpscan inspect --connect <target>   # show the text the model reads, hidden characters revealed
```

Supported clients: Claude Desktop, Claude Code, Cursor, VS Code, Windsurf, Zed, Cline, Roo Code,
Gemini CLI, Codex CLI, Continue, Goose, Amazon Q Developer CLI, Kiro, opencode and LM Studio, on
macOS, Linux and Windows. See [docs/CLIENTS.md](docs/CLIENTS.md) for paths and formats.
Reports never contain secret values.

### Policy file

`.mcpscan.yaml` in the current directory (or `--policy PATH`) sets defaults and suppresses
findings you've reviewed. Suppressed findings stay in JSON and SARIF output, marked with their
reason.

```yaml
fail_on: high
strict: true            # exit 2 if any server couldn't be connected to
suppress:
  - rule_id: MCP-CF-001
    server: internal-db
    reason: Secret is injected by vault at runtime   # required
    expires: 2027-01-01                               # optional
  - rule_id: "MCP-TP-*"   # globs work for rule_id, server and tool
    server: docs-search
    reason: Reviewed 2026-10; descriptions quote attack examples on purpose
```

### What `--connect` does

It sends only listing requests (`initialize`, `tools/list`, `prompts/list`, `resources/list`);
no tool is ever called. Tools are listed twice to catch servers that change them mid-session.

- **stdio servers** run in a Docker sandbox by default. The package is downloaded with network
  access but without running any of its code (`npm install --ignore-scripts`, wheels only for
  PyPI), then the server runs with no network, a read-only filesystem, no capabilities, a
  non-root user and resource limits. Servers that run local files can't be sandboxed this way;
  `--sandbox none` runs servers directly on this machine, as your MCP client would.
- **Env vars** get dummy values unless you pass `--real-credentials` (which also expands
  `${VAR}` references). Most servers list their tools without valid credentials.
- **Remote servers** are reached without credentials unless you pass `--real-credentials`
  (the config's headers), `--header` (for a single URL target only, so a token can't reach
  another server) or `--oauth` (signs in through your browser; tokens stay in memory for that
  run). A server that answers without credentials is reported (MCP-CF-003).
- **Servers run in parallel**, four at a time (`--jobs`). npm and uv downloads are cached in the
  Docker volumes `mcpscan-npm-cache` and `mcpscan-uv-cache`; remove them with
  `docker volume rm` to start fresh.
- **Locking** with `--connect` also pins the package version or image digest that actually ran,
  so `verify` catches an unpinned `npx -y pkg` quietly moving to a new release.
- **Opt-ins** for servers that won't start otherwise: `--allow-network` (network while running)
  and `--allow-install-scripts` (npm install scripts and PyPI source builds during download).
  Both are off by default.
- **`--save-snapshots DIR`** keeps what each server served, so it can be rescanned offline.
- **Disabled servers** (disabled in their client config) aren't started.
- **Older servers** that crash on the 2026 `server/discover` probe are retried in a fresh
  process with the classic `initialize` handshake.
- **Versions can differ from your machine's**: npm picks the newest release whose `engines`
  match the sandbox's Node 22 (`MCPSCAN_NODE_IMAGE` overrides the image), so an unpinned package
  may resolve differently than on a machine with a newer Node.

## Calibration

The tool-metadata rules are tuned against the 100 most-downloaded servers in the official MCP
registry: zero false positives on the 59 the sandbox could list, with the attack fixtures still
detected. Method, scripts and results: [calibration/README.md](calibration/README.md).

## Development

```bash
uv sync
uv run mcpscan scan fixtures/metadata/unicode-tag-smuggling/snapshots.json
uv run mcpscan scan fixtures/configs/claude_desktop_config.json
uv run mcpscan inspect fixtures/metadata/unicode-tag-smuggling/snapshots.json
uv run pytest                     # MCPSCAN_DOCKER_TESTS=1 also runs a real Docker sandbox
uv run ruff check . && uv run ruff format --check . && uv run pyright
```

## Adding a rule

1. Reserve an id in `docs/RULES.md`.
2. Add a module under `src/mcpscan/rules/builtin/` with a `Rule` subclass decorated with
   `@register` (see `invisible_unicode.py`). Iterate text with `iter_text_fields` so nested schema
   text is covered.
3. List the id in `expected.json` for each fixture case it should fire on, and add a benign
   look-alike case. `tests/test_fixtures.py` then checks it everywhere.
4. Build any invisible or look-alike characters with `chr()`; `tests/test_source_hygiene.py`
   fails on raw ones in the source.

Third-party rule packs can register through the `mcpscan.rules` entry-point group.

# MCPiranha

Security scanner for Model Context Protocol (MCP) servers: tool poisoning, cross-server shadowing,
rug pulls, insecure configuration, vulnerable implementations and dangerous combinations of servers.
It works fully offline. Design: [docs/ARCHITECTURE.md](https://github.com/ethanroubal/MCP-Server-Security-Scanner/blob/main/docs/ARCHITECTURE.md).

**Status: 0.1.0.** 24 rules (see [docs/RULES.md](https://github.com/ethanroubal/MCP-Server-Security-Scanner/blob/main/docs/RULES.md)) run on client configs, snapshot
files and, with `--connect`, on what servers actually serve. Toxic-flow analysis across servers
is in; an experimental local classifier is optional; an LLM layer is planned.

## Install

```bash
uvx mcpiranha scan              # run without installing (needs uv)
pipx install mcpiranha          # or install the command
pip install 'mcpiranha[ml]'     # with the experimental classifier
```

Requires Python 3.12+. `--connect` uses Docker for its sandbox.

## Usage

```bash
mcpiranha scan                      # every MCP client config on this machine + the current project
mcpiranha scan .mcp.json            # one config file (Claude, Cursor, VS Code, Windsurf formats)
mcpiranha scan ./some-project       # a project's .mcp.json, .cursor/mcp.json, .vscode/mcp.json
mcpiranha scan --connect            # also start/reach each server and check its tools, prompts, resources
mcpiranha scan --connect npm:@scope/server@1.2.3   # vet a package before installing it
mcpiranha scan --connect https://mcp.example.com/mcp --oauth          # sign in (opens a browser)
mcpiranha scan --connect https://mcp.example.com/mcp -H "Authorization: Bearer $TOKEN"
mcpiranha scan --connect --strict   # CI: exit 2 if any server couldn't be checked
mcpiranha scan -f sarif -o mcpiranha.sarif   # for GitHub code scanning
mcpiranha lock --connect            # pin launch configs and tool definitions to mcp-lock.json
mcpiranha verify --connect          # exit 1 if anything changed or was added since the lock
mcpiranha inspect --connect <target>   # show the text the model reads, hidden characters revealed
mcpiranha flows                     # each client's tool capabilities and the toxic flows between them
mcpiranha scan --offline            # no registry / osv.dev lookups or package downloads
mcpiranha scan --no-deps            # online, but skip dependency trees
mcpiranha scan --classifier         # experimental: add the local ML classifier (pip install 'mcpiranha[ml]')
mcpiranha bench                     # in a checkout: score against the zoo of known-bad servers
```

Supported clients: Claude Desktop, Claude Code, Cursor, VS Code, Windsurf, Zed, Cline, Roo Code,
Gemini CLI, Codex CLI, Continue, Goose, Amazon Q Developer CLI, Kiro, opencode and LM Studio, on
macOS, Linux and Windows. See [docs/CLIENTS.md](https://github.com/ethanroubal/MCP-Server-Security-Scanner/blob/main/docs/CLIENTS.md) for paths and formats.
Reports never contain secret values.

### Toxic flows

Servers that are harmless alone can be dangerous together. mcpiranha labels every tool (reads
untrusted content, reads private data, sends data out, runs code, destroys data) from its name,
its parameters and a table of well-known servers, then looks across all servers one client
loads. **MCP-TF-001** reports the "lethal trifecta", e.g. `github.get_issue -> filesystem.read_file
-> slack.post_message`: one poisoned issue can make the agent read your files and post them.
**MCP-TF-002** reports untrusted content next to code execution or destructive tools. Flows across
servers are high severity (critical if the last step is auto-approved); flows inside a single
server, which are usually by design, are lower. Well-known servers count even without
`--connect`.

### Supply chain

`scan` looks every npm and PyPI package a config runs up on the registry and on
[osv.dev](https://osv.dev): the release `npx`/`uvx` would install (or, with `--connect`, the one
that was installed), its publisher, install scripts, provenance and the release before it.
**MCP-SC-001** reports known vulnerabilities and known malware (e.g. `mcp-remote@0.1.15`,
CVE-2025-6514; `postmark-mcp@1.0.16`, taken down and listed as MAL-2025-47604).
**SC-002** install scripts (high when the release just added one), **SC-003** a release that lost
its build provenance or moved to another owner's repository, **SC-004** a package under 30 days
old, **SC-005** a release by an npm account that never published the package before, **SC-006**
deprecated or yanked releases and names missing from the registry (which anyone could register).
This sends package names and versions to those services; `--offline` (or
`MCPIRANHA_OFFLINE=1`) turns it off. `MCPIRANHA_NPM_REGISTRY` / `MCPIRANHA_PYPI_INDEX` point
at a mirror. Docker images aren't looked up yet.

**Dependencies** get the same treatment (`--no-deps` turns it off): the tree npx/uvx would
install is resolved from registry metadata (npm ranges and aliases; PyPI Requires-Dist with
markers evaluated for the sandbox's Python), up to 400 packages, and every dependency is checked
against OSV. **SC-007** reports known malicious (critical) or vulnerable dependencies, **SC-008**
dependencies that run code at install (low; high when a release from the last 30 days just added
it), **SC-009** suspicious ones: a name the registry doesn't have, a git or URL dependency, or a
recent release with a new publisher or without the provenance its predecessor had. Install
scripts' command lines are judged as executed commands, and the code of dependencies that run at
install or look hijacked is read with the MCP-SRC rules (paths show `name@version/file`). Each
finding names the chain that pulls the dependency in (`server > lib > leaf`).

### Source analysis

mcpiranha also reads the code a server runs, without running it: a local script the config
launches (`python server.py`, `node build/index.js`), or, online, the npm tarball or PyPI wheel
of the resolved release, checked against the registry's hash and read in memory (nothing is
extracted or installed). Python is parsed with `ast`, JavaScript/TypeScript (bundles and
minified output included) with tree-sitter. The MCP-SRC rules look for malice behind honest
metadata: **SRC-001** a fixed address added as Bcc/Cc (how postmark-mcp copied every email),
**SRC-002** collecting secrets from the environment, **SRC-003** credential paths in code that
also has a way out, **SRC-004** running decoded, downloaded or obfuscated code, **SRC-005** a
hardcoded request catcher, tunnel or Discord webhook, **SRC-006** reverse shells, **SRC-007**
miners, **SRC-008** persistence (writing shell profiles, LaunchAgents, cron), **SRC-009** writing
MCP client configs, **SRC-010** wipers. Command strings only count when executed and config paths
only when written, since deny-lists and installers are full of both.

**Exploitable tool handlers** (taint analysis): tool arguments are followed from the handler
(`server.tool(...)`, `registerTool`, `@mcp.tool()`, low-level `call_tool` handlers) through
assignments and into functions across the package's files. **SRC-101** command injection,
**SRC-102** SQL injection, **SRC-103** path traversal, **SRC-104** SSRF. Only input spliced into
code the developer wrote counts: ``execSync(`git log ${branch}`)`` is reported, a shell tool
running the `command` it's given is a capability (the toxic-flow rules cover that), not a bug.
It flags the vulnerable releases of two servers with published command-injection CVEs, and
stays quiet on their fixes.

### Server behavior during a session

With `--connect`, mcpiranha also reads prompt bodies and static resource contents and keeps log
notifications, so poisoning there is caught like poisoning in descriptions. It advertises
sampling, elicitation and roots like a real client (over the classic protocol too, where servers
can send such requests mid-call), declines every request, and reports a server that uses your
model, maps your workspace (**DY-001**) or asks you for input, worst when it's a password or token
(**DY-002**), while it was only being listed.

### Experimental classifier

`--classifier` adds a local prompt-injection model (protectai/deberta-v3-base-prompt-injection-v2,
Apache-2.0, ~740 MB, downloaded once and verified against pinned hashes). It catches some reworded
attacks the phrase rules miss, but it was trained on chat prompts and flags ordinary usage
guidance in tool descriptions too, so its findings are low severity and meant as a review
queue. Measurements: [calibration/README.md](https://github.com/ethanroubal/MCP-Server-Security-Scanner/blob/main/calibration/README.md).

### Policy file

`.mcpiranha.yaml` in the current directory (or `--policy PATH`) sets defaults and suppresses
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
  Docker volumes `mcpiranha-npm-cache` and `mcpiranha-uv-cache`; remove them with
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
  match the sandbox's Node 22 (`MCPIRANHA_NODE_IMAGE` overrides the image), so an unpinned package
  may resolve differently than on a machine with a newer Node.

## Calibration

The tool-metadata rules are tuned against the 100 most-downloaded servers in the official MCP
registry: zero false positives on the 59 the sandbox could list, with the attack fixtures still
detected. Method, scripts and results: [calibration/README.md](https://github.com/ethanroubal/MCP-Server-Security-Scanner/blob/main/calibration/README.md).

The supply-chain rules were run on the same 85 npm/PyPI servers, pinned and unpinned: no false
publisher or provenance alarms, one package with 159 advisories, two yanked or deprecated
releases, and one registry config that runs a PyPI name nobody owns. The source rules read
19,000 files across their releases with no findings.

Attacks are tested against [the zoo](https://github.com/ethanroubal/MCP-Server-Security-Scanner/blob/main/zoo/README.md): 48 safe-by-construction
malicious and vulnerable servers, configs and packages, including reconstructions of public
incidents and hijacked or backdoored releases (and dependencies) served from local registries.
They're organized by a [threat catalog](https://github.com/ethanroubal/MCP-Server-Security-Scanner/blob/main/zoo/threats.yaml) of 63 ways an MCP server can act
maliciously, which a test keeps in sync with the rules: 54 are detected, 4 partly, and 5 are
tracked gaps (tool output, repository diffs, and runtime egress, file access and time bombs).

## Development

```bash
uv sync --all-extras
uv run mcpiranha scan fixtures/metadata/unicode-tag-smuggling/snapshots.json
uv run mcpiranha scan fixtures/configs/claude_desktop_config.json
uv run mcpiranha inspect fixtures/metadata/unicode-tag-smuggling/snapshots.json
uv run pytest                     # MCPIRANHA_DOCKER_TESTS=1 also runs a real Docker sandbox
uv run ruff check . && uv run ruff format --check . && uv run pyright
```

## Adding a rule

1. Reserve an id in `docs/RULES.md`.
2. Add a module under `src/mcpiranha/rules/builtin/` with a `Rule` subclass decorated with
   `@register` (see `invisible_unicode.py`). Iterate text with `iter_text_fields` so nested schema
   text is covered.
3. List the id in `expected.json` for each fixture case it should fire on, and add a benign
   look-alike case. `tests/test_fixtures.py` then checks it everywhere.
4. Build any invisible or look-alike characters with `chr()`; `tests/test_source_hygiene.py`
   fails on raw ones in the source.

Third-party rule packs can register through the `mcpiranha.rules` entry-point group.

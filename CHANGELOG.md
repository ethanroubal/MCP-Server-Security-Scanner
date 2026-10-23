# Changelog

## 0.2.0 — 2026-10-23

`scan` now looks past what a server shows the model: the package it runs, the code inside it,
everything it installs, and what it does during a session. Lookups go to npm, PyPI and osv.dev;
`--offline` turns them off, `--no-deps` skips dependency trees.

### Supply chain (MCP-SC-001..009)
- Resolves the release npx/uvx would run and checks it against OSV: known vulnerabilities and
  malware, even for packages the registry took down (postmark-mcp).
- Install scripts, lost build provenance, brand-new packages, releases by a new npm account,
  deprecated or yanked releases, and package names nobody owns.
- Dependency trees: every dependency checked against OSV, for install scripts, and for hijack
  signals on recent releases; each finding names the chain that pulls it in.

### Source analysis (MCP-SRC)
- Reads local server scripts, and the npm tarball or PyPI wheel of the release (hash-checked,
  read in memory, never installed). Python via `ast`, JavaScript/TypeScript via tree-sitter.
- Hidden behavior (SRC-001..010): fixed Bcc/Cc recipients, environment harvesting, credential
  theft, decoded/downloaded/obfuscated code, request catchers, reverse shells, miners,
  persistence, MCP client config writes, wipers.
- Exploitable tool handlers (SRC-101..104): taint from tool arguments to shell commands, SQL,
  file paths and URL hosts, across a package's files. Flags the vulnerable releases for
  CVE-2025-53355 and CVE-2025-52573 and not their fixes.
- The code of dependencies that run at install or look hijacked is read too.

### Session checks (with `--connect`)
- Reads prompt bodies, static resource contents and log notifications, and checks them like
  descriptions.
- Records sampling, roots and elicitation requests a server sends while only being listed
  (MCP-DY-001/002), also over the classic protocol where servers can send them mid-request.
- Scans earlier versions of tools that change mid-session (rug pulls).
- Opens only http(s) OAuth authorization URLs (CVE-2025-6514).

### Testing
- `mcpiranha bench` scores the scanner against the zoo: 48 safe-by-construction malicious and
  vulnerable servers, configs and packages, some served from local npm/PyPI registries.
- `zoo/threats.yaml` catalogs 63 ways an MCP server can act maliciously (54 detected, 4 partly,
  5 tracked gaps); a test keeps it in sync with the rules.
- Calibrated on the 100 most-downloaded registry servers: see `calibration/README.md`.

### Other
- Cross-server toxic-flow labels tightened on real server combinations.
- New dependencies: tree-sitter (JavaScript/TypeScript grammars), packaging.

## 0.1.0 — 2026-10-22

First release: client config discovery (16 clients), config and tool-metadata rules,
sandboxed `--connect`, lockfiles, policies, toxic flows, an experimental local classifier, and
TTY/JSON/SARIF output.

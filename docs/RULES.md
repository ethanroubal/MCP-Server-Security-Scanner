# Rule catalog

Ids are permanent: never renumber or reuse one. Status: ✅ implemented, ⬜ planned.
Sections refer to docs/ARCHITECTURE.md §5. Tool-metadata rules were tuned against the 100
most-downloaded registry servers; see calibration/README.md.

## MCP-TP — Tool poisoning (§5.1)
| Id | Title | Status |
|---|---|---|
| MCP-TP-001 | Invisible or smuggled Unicode characters | ✅ |
| MCP-TP-002 | Terminal escape sequences | ✅ |
| MCP-TP-003 | Directive markup (`<IMPORTANT>`, `<system>`, fake role markers) | ✅ |
| MCP-TP-004 | Instructions steering the model against the user | ✅ |
| MCP-TP-005 | Instructions involving credentials or sensitive files | ✅ |
| MCP-TP-006 | Encoded payloads (base64 / hex) | ✅ |
| MCP-TP-007 | Exfiltration via rendered links or images | ✅ |
| MCP-TP-008 | Padding that pushes suspicious text out of view | ✅ |
| MCP-TP-009 | Exfiltration-shaped parameters | ✅ |
| MCP-TP-010 | Sentence classified as a prompt injection (`--classifier`, experimental) | ✅ |

## MCP-XS — Cross-server (§5.2)
| Id | Title | Status |
|---|---|---|
| MCP-XS-001 | Description references another server's tools | ✅ |
| MCP-XS-002 | Tool name collision or confusable look-alike | ✅ |
| MCP-XS-003 | Server name typosquat | ✅ |

## MCP-RP — Rug pulls & integrity (§5.3)
| Id | Title | Status |
|---|---|---|
| MCP-RP-001 | Tool definition changed since lock | ✅ |
| MCP-RP-002 | Tools changed during a session (`--connect`) | ✅ |
| MCP-RP-003 | Floating (unpinned) package version | ✅ |

## MCP-CF — Configuration & transport (§5.4)
| Id | Title | Status |
|---|---|---|
| MCP-CF-001 | Plaintext secret in client config | ✅ |
| MCP-CF-002 | Remote server over plain HTTP | ✅ |
| MCP-CF-003 | Remote server without authentication (`--connect`) | ✅ |
| MCP-CF-004 | Dangerous launcher (`curl \| sh`, `--privileged`, host mounts) | ✅ |
| MCP-CF-005 | Over-broad filesystem scope | ✅ |
| MCP-CF-006 | Tool calls approved without confirmation (client auto-approve settings) | ✅ |

## MCP-TF — Toxic flows across servers (§5.7)
| Id | Title | Status |
|---|---|---|
| MCP-TF-001 | Untrusted input, private data and an outbound channel in one agent | ✅ |
| MCP-TF-002 | Untrusted input and code execution or destructive tools in one agent | ✅ |

## MCP-SC — Supply chain (§5.6)
Judged on registry and OSV data gathered before the scan (`mcpiranha.supply`); off with `--offline`.

| Id | Title | Status |
|---|---|---|
| MCP-SC-001 | Known vulnerability (OSV) or known malicious package (OSV `MAL-`) | ✅ |
| MCP-SC-002 | Package runs code at install time (npm lifecycle scripts, sdist-only PyPI release); high when just added | ✅ |
| MCP-SC-003 | Release lost its build provenance, or was built from another owner's repository | ✅ |
| MCP-SC-004 | Very new package (under 30 days) | ✅ |
| MCP-SC-005 | Release published by an npm account that never published the package before | ✅ |
| MCP-SC-006 | Deprecated or yanked release, or a package name missing from the registry | ✅ |

## MCP-SRC — Source code (§5.5)
Judged on what `mcpiranha.source` finds in a local script or the package's release archive.

| Id | Title | Status |
|---|---|---|
| MCP-SRC-001 | Code adds a fixed Bcc/Cc recipient | ✅ |
| MCP-SRC-002 | Code collects secrets from the environment (serializes it, or reads TOKEN/KEY values) | ✅ |
| MCP-SRC-003 | Code names credential files and has a way to send data out | ✅ |
| MCP-SRC-004 | Code runs decoded or downloaded code (`eval(atob(...))`, `exec(b64decode(...))`) | ✅ |
| MCP-SRC-005 | Code contains a request-catcher, tunnel or Discord webhook address | ✅ |
| MCP-SRC-1xx | Taint from tool arguments to command / path / URL / SQL sinks | planned |

MCP-DY ids will be added with Phase 4.

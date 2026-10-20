# Rule catalog

Ids are permanent: never renumber or reuse one. Status: ✅ implemented, ⬜ planned.
Sections refer to docs/ARCHITECTURE.md §5.

## MCP-TP — Tool poisoning (§5.1)
| Id | Title | Status |
|---|---|---|
| MCP-TP-001 | Invisible or smuggled Unicode characters | ✅ |
| MCP-TP-002 | Terminal escape sequences | ⬜ |
| MCP-TP-003 | Directive markup (`<IMPORTANT>`, `<system>`, fake role markers) | ⬜ |
| MCP-TP-004 | Instruction phrases aimed at the model | ⬜ |
| MCP-TP-005 | Sensitive path or secret references | ⬜ |
| MCP-TP-006 | Encoded payloads (base64 / hex) | ⬜ |
| MCP-TP-007 | Exfiltration via rendered links or images | ⬜ |
| MCP-TP-008 | Padding / description length anomaly | ⬜ |
| MCP-TP-009 | Exfiltration-shaped parameters | ⬜ |

## MCP-XS — Cross-server (§5.2)
| Id | Title | Status |
|---|---|---|
| MCP-XS-001 | Description references another server's tools | ⬜ |
| MCP-XS-002 | Tool name collision or confusable look-alike | ⬜ |
| MCP-XS-003 | Server name typosquat | ⬜ |

## MCP-RP — Rug pulls & integrity (§5.3)
| Id | Title | Status |
|---|---|---|
| MCP-RP-001 | Tool definition changed since lock | ⬜ |
| MCP-RP-002 | Tools changed during a session | ⬜ |
| MCP-RP-003 | Floating (unpinned) package version | ⬜ |

## MCP-CF — Configuration & transport (§5.4)
| Id | Title | Status |
|---|---|---|
| MCP-CF-001 | Plaintext secret in client config | ⬜ |
| MCP-CF-002 | Remote server over plain HTTP | ⬜ |
| MCP-CF-003 | Remote server without authentication | ⬜ |
| MCP-CF-004 | Dangerous launcher (`curl \| sh`, `--privileged`, host mounts) | ⬜ |
| MCP-CF-005 | Over-broad filesystem scope | ⬜ |

MCP-SRC, MCP-SC, MCP-TF and MCP-DY ids will be added with Phases 3–4.

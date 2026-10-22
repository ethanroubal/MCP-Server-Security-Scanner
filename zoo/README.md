# The zoo

Known-bad MCP servers, written to test mcpiranha against attacks rather than against its own
fixtures. Each sample reconstructs an attack class or a public incident, says which rules a
correct scan must report, and `mcpiranha bench` checks that it does:

```bash
uv run mcpiranha bench                      # every sample
uv run mcpiranha bench --only rug-pull      # one sample
uv run mcpiranha bench -f json
```

`tests/test_bench.py` runs the whole zoo, so a rule change that stops detecting a sample fails CI.

## Safety rules

Samples are safe by construction, which is why `bench` runs them on the host like the tests:

- **No real malware.** Every sample is written here, never downloaded. Incident reconstructions
  copy the technique (what the model is shown, or what the code does), not the original code.
- **Nothing leaves the machine.** No sample opens a network connection or writes a file. Where an
  attack would send data (a BCC address, an "audit" URL), the destination is on the reserved
  `.invalid` domain and the data stays in memory. Secrets read from the environment are the
  sandbox's dummy values.
- **Never published.** Samples aren't packaged or pushed to npm, PyPI or an image registry.
  Supply-chain samples (install scripts, typosquats that actually install) will use local
  registries (Verdaccio, pypiserver, a local image registry) when Phase 3 starts.
- **Invisible characters are built at runtime** (`chr(...)`), so the source stays readable and
  `tests/test_source_hygiene.py` still passes.

## Samples

| Sample | Attack | Detected by |
|---|---|---|
| `tool-poisoning` | `<IMPORTANT>` block asking for `~/.ssh/id_rsa` in a hidden parameter ([Invariant Labs](https://invariantlabs.ai/blog/mcp-security-notification-tool-poisoning-attacks)) | TP-003, TP-004, TP-005, TP-009 |
| `paraphrased-override` | Override and exfiltration worded to avoid the usual phrases | TP-004, TP-005 |
| `hidden-unicode` | Instructions in Unicode tag characters | TP-001, TP-005, TP-009 |
| `terminal-escapes` | ANSI codes hiding text from a human reviewer ([Trail of Bits](https://blog.trailofbits.com/2025/04/29/deceiving-users-with-ansi-terminal-codes-in-mcp/)) | TP-002, TP-005 |
| `render-exfil` | Markdown image whose URL carries the conversation | TP-007 |
| `rug-pull` | Clean on the first `tools/list`, poisoned on the next | RP-002, TP-004, TP-005 |
| `whatsapp-shadowing` | Sleeper "fact of the day" server redirecting another server's `send_message` ([Invariant Labs](https://invariantlabs.ai/blog/whatsapp-mcp-exploited)) | RP-002, XS-001, TP-003, TF-001 |
| `cross-server-trifecta` | Three clean servers: inbox + files + webhook | TF-001 |
| `github-issue-leak` | Official GitHub server alone: public issue to private repo to public PR ([Invariant Labs](https://invariantlabs.ai/blog/mcp-github-vulnerability)); config only | TF-001, RP-003 |
| `typosquat-config` | `@modelcontextprotoco/server-filesystem`; config only | XS-003, RP-003 |
| `postmark-bcc` | Clean metadata, send tool quietly adds a BCC ([Koi Security](https://www.koi.ai/blog/postmark-mcp-npm-malicious-backdoor-email-theft)) | gap: needs source analysis (Phase 3) |
| `poisoned-tool-output` | Injection in a tool's result, not its description | gap: needs tool calls (dynamic analysis) |
| `startup-env-harvest` | Reads every secret-looking env var at startup | gap: needs runtime monitoring (Phase 4) |

The OAuth half of [CVE-2025-6514](https://jfrog.com/blog/2025-6514-critical-mcp-remote-rce-vulnerability/)
(mcp-remote opened a server-supplied authorization URL as given) is a test of the scanner
itself: `--oauth` opens only http(s) URLs (`tests/test_connect.py`).

## Adding a sample

A directory under `samples/` with the server code and a `sample.yaml`:

```yaml
title: One line
attack: tool-poisoning          # free-form class, shown in the report
source: https://...             # the incident or write-up it reconstructs, if any
connect: true                   # false: config only, nothing launched
servers:                        # client-config entries; installed together, as one client
  name: {command: "${PYTHON}", args: ["${SAMPLE}/server.py"]}
expect: [MCP-TP-004]            # rules a correct scan must report
gap: Why it can't be detected yet, and what closes it   # instead of `expect`
```

`bench` reports a sample as **pass** (every expected rule fired), **fail** (one didn't), **gap**
(known blind spot) or **gap-flagged** (a known gap now gets findings: review it and turn the
gap into `expect`). Rules that fire beyond `expect` are listed but don't fail the sample.

Don't tune a rule on a sample and then count that sample as evidence it works. New attacks are
worth more written by someone who hasn't read the rules: a held-out set, scored before any rule
change it prompts.

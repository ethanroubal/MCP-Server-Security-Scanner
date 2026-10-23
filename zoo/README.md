# The zoo

Known-bad MCP servers, written to test mcpiranha against attacks rather than against its own
fixtures. Each sample reconstructs an attack class or a public incident, says which rules a
correct scan must report, and `mcpiranha bench` checks that it does:

```bash
uv run mcpiranha bench                      # every sample
uv run mcpiranha bench --only rug-pull      # one sample
uv run mcpiranha bench -f json
uv run python zoo/registries/registries.py up   # first, for the supply-chain (sc-*) samples
```

Supply-chain samples look packages up, so `--offline` skips them, as does `bench` when their
local registries aren't running.

`tests/test_bench.py` runs the whole zoo, so a rule change that stops detecting a sample fails CI
(the supply-chain samples in the Docker job, against the local registries).

## Safety rules

Samples are safe by construction, which is why `bench` runs them on the host like the tests:

- **No real malware.** Every sample is written here, never downloaded. Incident reconstructions
  copy the technique (what the model is shown, or what the code does), not the original code.
- **Nothing leaves the machine.** No sample opens a network connection or writes a file. Where an
  attack would send data (a BCC address, an "audit" URL), the destination is on the reserved
  `.invalid` domain and the data stays in memory. Secrets read from the environment are the
  sandbox's dummy values.
- **Never published publicly.** Supply-chain samples are published only to local registries
  (`zoo/registries/registries.py up` starts verdaccio and pypiserver on 127.0.0.1, with no
  uplink to the public registries). Their install scripts and setup.py are inert, and nothing
  installs them: mcpiranha only reads registry metadata. Two samples look up real packages
  (`postmark-mcp`, `mcp-remote`) on the public registry and osv.dev, without downloading them.
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
| `sc-install-script-added` | A new npm account publishes a release that adds a postinstall script (local registry) | SC-002, SC-004, SC-005, RP-003 |
| `sc-provenance-dropped` | A release without the provenance the previous one had (local registry) | SC-003, SC-004, RP-003 |
| `sc-sdist-only` | A PyPI release with only a source distribution, so setup.py runs on install (local index) | SC-002, RP-003 |
| `sc-known-malicious` | The real `postmark-mcp@1.0.16`: taken down, listed as malware in OSV | SC-001, SC-006 |
| `sc-known-vulnerable` | The real `mcp-remote@0.1.15` (CVE-2025-6514) | SC-001 |
| `postmark-bcc` | Clean metadata, send tool quietly adds a BCC ([Koi Security](https://www.koi.ai/blog/postmark-mcp-npm-malicious-backdoor-email-theft)); local script | SRC-001 |
| `sc-backdoored-mailer` | The same BCC inside an npm release (local registry; tarball read in memory) | SRC-001, SC-004 |
| `sc-hidden-payload` | A wheel that runs a base64-encoded payload on import (local index) | SRC-004 |
| `startup-env-harvest` | Collects every secret-looking env var at startup | SRC-002 |
| `credential-stealer` | Credential paths next to a webhook.site collector (literals only, never launched) | SRC-003, SRC-005 |
| `poisoned-tool-output` | Injection in a tool's result, not its description | gap: needs tool calls (dynamic analysis) |

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
lookup: true                    # supply-chain sample: look packages up on npm/PyPI and OSV
registries: {npm: "http://127.0.0.1:4873"}   # ...in these registries instead (implies lookup)
```

`bench` reports a sample as **pass** (every expected rule fired), **fail** (one didn't), **gap**
(known blind spot) or **gap-flagged** (a known gap now gets findings: review it and turn the
gap into `expect`). Rules that fire beyond `expect` are listed but don't fail the sample.

Don't tune a rule on a sample and then count that sample as evidence it works. New attacks are
worth more written by someone who hasn't read the rules: a held-out set, scored before any rule
change it prompts.

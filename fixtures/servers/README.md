# Fixture MCP servers

Small, deliberately malicious (or merely probing) MCP servers for the `--connect` tests in
`tests/test_connect.py`. They are mcpiranha's own test code, so tests run them with
`--sandbox none`. None of them reads files, touches the network or does anything when a tool is
called; the malice is only in what they *show* the model.

| Server | What it does |
|---|---|
| `poisoned.py` | Tool-poisoning description, an exfiltration parameter, plus a prompt and a resource |
| `rug_pull.py` | Serves a clean tool on the first `tools/list`, a poisoned one on the second |
| `structured_poison.py` | Inert structured-schema injection on the first listing, then clean metadata; omit `--malicious` for the clean twin |
| `env_probe.py` | Puts the value of `PROBE_TOKEN` into its tool description, to check what env it got |
| `http_open.py` | Streamable-HTTP server with no auth and a state-changing tool; port from argv |
| `http_oauth.py` | Requires OAuth (built-in authorization server that approves every sign-in) or the token `static-test-token`; port from argv |

`dynamic_probe.py` is a stdlib-only Docker regression server. It reads a credential file
only under the harness's synthetic HOME and probes only the harness's default-deny proxy.
Its tool output exercises injection detection after explicit invocation.


`dynamic_adversarial.py` refuses to run outside the synthetic HOME. Its modes exercise
credential access before an initialization crash, relative and directory-FD opens, attempts
to tamper with collector files/processes, direct TCP and DNS attempts, delayed access,
expected proxy traffic, and nested fuzz inputs reaching synthetic sinks. A benign mode is
the control. All credential/canary files are fake; network targets use reserved addresses.


Additional `dynamic_adversarial.py` modes cover inherited/duplicated descriptor reads,
readable mappings, hard-link aliases, directory renames and rejected baseline arguments.
`tests/test_dynamic_files.py` checks descriptor sharing, close/reuse, close-on-exec and alias
replacement. `tests/test_dynamic_validation.py` checks baseline rejection, blocked external
schema retrieval and bounded pathological patterns; no real credential data is used.

# Fixture MCP servers

Small, deliberately malicious (or merely probing) MCP servers for the `--connect` tests in
`tests/test_connect.py`. They are mcpiranha's own test code, so tests run them with
`--sandbox none`. None of them reads files, touches the network or does anything when a tool is
called; the malice is only in what they *show* the model.

| Server | What it does |
|---|---|
| `poisoned.py` | Tool-poisoning description, an exfiltration parameter, plus a prompt and a resource |
| `rug_pull.py` | Serves a clean tool on the first `tools/list`, a poisoned one on the second |
| `env_probe.py` | Puts the value of `PROBE_TOKEN` into its tool description, to check what env it got |
| `http_open.py` | Streamable-HTTP server with no auth and a state-changing tool; port from argv |
| `http_oauth.py` | Requires OAuth (built-in authorization server that approves every sign-in) or the token `static-test-token`; port from argv |

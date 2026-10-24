"""Paths seeded by the trusted launcher, shared by acquisition and offline rules."""

HOME = "/tmp/mcpiranha-home"
HONEY_PATHS = (".ssh/id_rsa", ".aws/credentials", ".env", ".config/chromium/Default/Cookies")
HONEYTOKENS = frozenset(f"{HOME}/{path}" for path in HONEY_PATHS)
CANARY = "/tmp/mcpiranha-canary"

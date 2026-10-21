"""MCP-CF-002: a remote server reached over plain HTTP.

Anyone on the network path can read the tool calls and results, steal auth headers, and rewrite
tool definitions in transit (an injection point that bypasses the server entirely).
"""

from __future__ import annotations

import ipaddress
from urllib.parse import urlsplit, urlunsplit

from mcpscan.core.models import Category, Evidence, Finding, Location, Severity
from mcpscan.rules.base import Rule, RuleContext
from mcpscan.rules.registry import register


def is_loopback(host: str) -> bool:
    if host == "localhost" or host.endswith(".localhost"):
        return True
    try:
        return ipaddress.ip_address(host).is_loopback
    except ValueError:
        return False


@register
class PlainHttp(Rule):
    id = "MCP-CF-002"
    title = "Remote server over plain HTTP"
    category = Category.CONFIG
    default_severity = Severity.HIGH
    applies_to = frozenset({"config"})
    remediation = "Use the server's https:// URL. If it has none, don't send it anything sensitive."

    def run(self, ctx: RuleContext) -> list[Finding]:
        launch = ctx.snapshot.launch
        if launch is None or not launch.url:
            return []
        parts = urlsplit(launch.url)
        if parts.scheme.lower() not in ("http", "ws") or is_loopback(parts.hostname or ""):
            return []
        sends_credentials = bool(launch.headers) or bool(parts.password)
        # Not the full URL: its userinfo or query string may hold a secret (see MCP-CF-001).
        port = f":{parts.port}" if parts.port else ""
        shown = urlunsplit((parts.scheme, f"{parts.hostname}{port}", parts.path, "", ""))
        return [
            self.finding(
                location=Location(
                    server_id=ctx.snapshot.id,
                    json_pointer="/launch/url",
                    file=ctx.snapshot.origin.config_path,
                ),
                evidence=[Evidence(text=shown)],
                rationale=f"{parts.hostname} is reached without TLS"
                + (", and the config sends credentials to it." if sends_credentials else "."),
                severity=Severity.HIGH,
            )
        ]

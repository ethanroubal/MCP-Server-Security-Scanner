"""Talk to a running MCP server and record everything it shows the model.

Only listing requests are sent (initialize, tools/list, prompts/list, resources/list,
resources/templates/list). No tool is ever called. Tools are listed twice, a moment apart, and
`list_changed` notifications are recorded: a server whose tools change mid-session is a rug pull
in progress (MCP-RP-002).
"""

from __future__ import annotations

from collections.abc import Awaitable, Callable
from dataclasses import dataclass, field
from typing import Any, Literal, cast

import anyio
import mcp_types as types
from mcp.client import Client, Transport
from mcp.shared.exceptions import MCPError

from mcpiranha import __version__
from mcpiranha.core.hashing import hash_json
from mcpiranha.core.models import (
    DynamicObservation,
    PromptDef,
    ResourceDef,
    ServerInfo,
    ToolDef,
)

MAX_PAGES = 50


class EnumerationError(Exception):
    pass


@dataclass
class Enumeration:
    server_info: ServerInfo | None = None
    tools: list[ToolDef] = field(default_factory=list[ToolDef])
    earlier_tools: list[ToolDef] = field(default_factory=list[ToolDef])
    prompts: list[PromptDef] = field(default_factory=list[PromptDef])
    resources: list[ResourceDef] = field(default_factory=list[ResourceDef])
    observations: list[DynamicObservation] = field(default_factory=list[DynamicObservation])


def _wire(model: Any) -> dict[str, Any]:
    return model.model_dump(mode="json", by_alias=True, exclude_none=True)


async def _all_pages(fetch: Callable[[str | None], Awaitable[Any]], key: str) -> list[Any]:
    items: list[Any] = []
    cursor: str | None = None
    for _ in range(MAX_PAGES):
        try:
            page = await fetch(cursor)
        except MCPError as exc:
            if exc.code == types.METHOD_NOT_FOUND:
                return items  # server doesn't support this list
            raise
        items.extend(getattr(page, key))
        cursor = page.next_cursor
        if not cursor:
            break
    return items


def _tool_changes(first: list[ToolDef], second: list[ToolDef]) -> str | None:
    before = {t.name: hash_json(t.wire_dump()) for t in first}
    after = {t.name: hash_json(t.wire_dump()) for t in second}
    if before == after:
        return None
    parts: list[str] = []
    for label, names in (
        ("changed", sorted(n for n in before.keys() & after.keys() if before[n] != after[n])),
        ("added", sorted(after.keys() - before.keys())),
        ("removed", sorted(before.keys() - after.keys())),
    ):
        if names:
            parts.append(f"{label}: {', '.join(names)}")
    return "; ".join(parts)


def _root_cause(exc: BaseException) -> BaseException:
    """The first leaf of nested exception groups (anyio task groups wrap transport errors)."""
    current = exc
    while inner := cast(tuple[BaseException, ...], getattr(current, "exceptions", ())):
        current = inner[0]
    return current


Handshake = Literal["auto", "legacy"]


async def enumerate_server(
    transport: Transport,
    *,
    timeout: float = 60.0,
    observe_seconds: float = 1.0,
    handshake: Handshake = "auto",
) -> Enumeration:
    """`handshake`: "auto" probes the 2026 `server/discover` first and falls back by itself on
    servers that answer with an error; "legacy" sends the classic `initialize`, for older servers
    that crash on the probe instead."""
    notifications: list[str] = []

    async def on_message(message: Any) -> None:
        if isinstance(message, types.ToolListChangedNotification):
            notifications.append("notifications/tools/list_changed")

    result = Enumeration()
    try:
        with anyio.fail_after(timeout):
            async with Client(
                transport,
                cache=None,  # rug-pull detection needs every listing fresh from the server
                mode=handshake,
                message_handler=on_message,
                read_timeout_seconds=timeout,
                client_info=types.Implementation(name="mcpiranha", version=__version__),
            ) as client:
                info: dict[str, Any] = _wire(client.server_info) if client.server_info else {}
                info.setdefault("name", "")
                if client.instructions:
                    info["instructions"] = client.instructions
                info["capabilities"] = _wire(client.server_capabilities)
                result.server_info = ServerInfo.model_validate(info)

                async def tools() -> list[ToolDef]:
                    raw = await _all_pages(lambda c: client.list_tools(cursor=c), "tools")
                    return [ToolDef.model_validate(_wire(t)) for t in raw]

                result.tools = await tools()
                prompts = await _all_pages(lambda c: client.list_prompts(cursor=c), "prompts")
                result.prompts = [PromptDef.model_validate(_wire(p)) for p in prompts]
                resources = await _all_pages(lambda c: client.list_resources(cursor=c), "resources")
                templates = await _all_pages(
                    lambda c: client.list_resource_templates(cursor=c), "resource_templates"
                )
                result.resources = [ResourceDef.model_validate(_wire(r)) for r in resources] + [
                    ResourceDef.model_validate({"uri": t.uri_template, **_wire(t)})
                    for t in templates
                ]

                await anyio.sleep(observe_seconds)
                first, result.tools = result.tools, await tools()
                changes = _tool_changes(first, result.tools)
                latest = {t.name: t for t in result.tools}
                result.earlier_tools = [t for t in first if latest.get(t.name) != t]
    except TimeoutError as exc:
        raise EnumerationError(f"no complete answer within {timeout:.0f}s") from exc
    except Exception as exc:
        cause = _root_cause(exc)
        raise EnumerationError(f"{type(cause).__name__}: {cause}") from exc

    if changes or notifications:
        detail = "; ".join(filter(None, [
            f"tools/list changed between two calls ({changes})" if changes else None,
            "server sent notifications/tools/list_changed" if notifications else None,
        ]))  # fmt: skip
        result.observations.append(
            DynamicObservation(kind="tools_changed", phase="listing", detail=detail)
        )
    return result

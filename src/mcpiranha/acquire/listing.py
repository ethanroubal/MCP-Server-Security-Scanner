"""Talk to a running MCP server and record everything it shows the model.

Only listing and reading requests are sent (initialize, tools/list, prompts/list, prompts/get
for prompts without required arguments, resources/list, resources/read for static resources,
resources/templates/list). Named --invoke tools are called only with explicit opt-in.
Tools are listed twice, a moment apart, and
`list_changed` notifications are recorded: a server whose tools change mid-session is a rug pull
in progress (MCP-RP-002).

mcpiranha advertises sampling, elicitation and roots like a real client, declines every such
request and records it (MCP-DY), and keeps the text of log notifications and requests so the
tool-poisoning rules read it too.
"""

from __future__ import annotations

import json
from collections.abc import Awaitable, Callable
from dataclasses import dataclass, field
from datetime import UTC, datetime
from typing import Any, Literal, cast

import anyio
import mcp_types as types
from mcp.client import Client, Transport
from mcp.shared.exceptions import MCPError

from mcpiranha import __version__
from mcpiranha.core.hashing import hash_json
from mcpiranha.core.models import (
    DynamicObservation,
    FetchedContent,
    ProbeRun,
    PromptDef,
    ResourceDef,
    ServerInfo,
    ToolDef,
)
from mcpiranha.dynamic.invoke import MAX_CALLS, cases
from mcpiranha.dynamic.validate import baseline

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
    content: list[FetchedContent] = field(default_factory=list[FetchedContent])
    protocol_version: str = ""
    probes: list[ProbeRun] = field(default_factory=list[ProbeRun])


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


MAX_CONTENT_ITEMS = 40
MAX_CONTENT_CHARS = 64_000
MAX_FETCHES = 20  # prompts and resources each
CONTENT_TIMEOUT = 10.0


def _short(text: str | None, limit: int = 200) -> str:
    text = " ".join((text or "").split())
    return text if len(text) <= limit else text[:limit] + "..."


def _content_text(content: Any) -> str:
    """Text of a content block, or of a list of them; other kinds (images, audio) give ""."""
    if isinstance(content, list):
        return "\n".join(_content_text(c) for c in cast(list[Any], content))
    if getattr(content, "type", None) == "text":
        return str(getattr(content, "text", ""))
    if getattr(content, "type", None) == "resource":
        return str(getattr(getattr(content, "resource", None), "text", "") or "")
    return ""


async def _fetch_content(client: Any, result: Enumeration, *, timeout: float) -> None:
    """Prompt bodies and resource contents, read the way a client would show them to the model.
    Both are reads by the spec; a server that fails or stalls on one is skipped, not an error.
    Only prompts without required arguments and static (non-template) text resources."""

    async def one(fetch: Any) -> Any:
        try:
            with anyio.fail_after(timeout):
                return await fetch()
        except Exception:  # the server's problem; listing goes on
            return None

    for prompt in result.prompts[:MAX_FETCHES]:
        if any(a.required for a in prompt.arguments):
            continue
        got = await one(lambda p=prompt: client.get_prompt(p.name, {}))
        text = "\n".join(_content_text(m.content) for m in getattr(got, "messages", []) or [])
        _Recorder(result).keep("prompt", prompt.name, text)
    static = [r for r in result.resources if "{" not in r.uri]
    for resource in static[:MAX_FETCHES]:
        got = await one(lambda r=resource: client.read_resource(r.uri))
        texts = [str(c.text) for c in getattr(got, "contents", []) or [] if hasattr(c, "text")]
        _Recorder(result).keep("resource", resource.uri, "\n".join(texts))


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


class _Recorder:
    """Acts like a client that supports sampling, elicitation and roots, so a server that would
    use them on a real client does here; records each request and declines it. Also keeps log
    notifications."""

    def __init__(self, result: Enumeration) -> None:
        self.result = result
        self.phase: Literal["startup", "listing", "invocation"] = "listing"
        self.probe_id: str | None = None

    def callbacks(self) -> dict[str, Any]:
        return {"sampling_callback": self.on_sampling, "elicitation_callback": self.on_elicitation,
                "list_roots_callback": self.on_roots, "logging_callback": self.on_log}  # fmt: skip

    def keep(self, kind: Any, ref: str, text: str) -> None:
        limit = MAX_CONTENT_ITEMS + MAX_CALLS if kind == "tool" else MAX_CONTENT_ITEMS
        if text.strip() and len(self.result.content) < limit:
            self.result.content.append(FetchedContent(kind=kind, ref=ref,
                                                      text=text[:MAX_CONTENT_CHARS],
                                                      probe_id=self.probe_id))  # fmt: skip

    def requested(self, kind: Any, detail: str, text: str = "") -> None:
        self.result.observations.append(
            DynamicObservation(kind=kind, phase=self.phase, detail=detail, probe_id=self.probe_id)
        )
        self.keep(kind.removesuffix("_request"), kind.removesuffix("_request"), text)

    async def on_sampling(self, context: Any, params: types.CreateMessageRequestParams) -> Any:
        texts = [_content_text(m.content) for m in params.messages]
        prompt = "\n".join(filter(None, [params.system_prompt, *texts]))
        self.requested("sampling_request", f"asked the client's model to write up to "
                       f"{params.max_tokens} tokens: {_short(prompt)}", prompt)  # fmt: skip
        return types.ErrorData(code=types.INVALID_REQUEST, message="declined by mcpiranha")

    async def on_elicitation(self, context: Any, params: types.ElicitRequestParams) -> Any:
        fields = sorted(_wire(params).get("requestedSchema", {}).get("properties", {}))
        url = getattr(params, "url", None)
        detail = (
            f"asked the user: {_short(params.message)}"
            + (f" (fields: {', '.join(fields)})" if fields else "")
            + (f" (url: {url})" if url else "")
        )
        self.requested("elicitation_request", detail, " ".join([params.message, *fields]))
        return types.ElicitResult(action="decline")

    async def on_roots(self, context: Any) -> Any:
        self.requested("roots_request", "asked for the client's roots (workspace paths)")
        return types.ListRootsResult(roots=[])

    async def on_log(self, params: types.LoggingMessageNotificationParams) -> None:
        text = params.data if isinstance(params.data, str) else json.dumps(params.data)
        self.keep("log", params.logger or "log", text)


async def observe_classic(transport: Transport, *, timeout: float = 30.0) -> Enumeration:
    """Read prompts and resources again over the classic (2025) protocol, recording what the
    server sends back. Servers can only send requests and logs to the client mid-request there;
    clients in use today mostly speak it, so a server that waits for them shows itself here."""
    result = Enumeration()
    recorder = _Recorder(result)
    with anyio.fail_after(timeout):
        async with Client(transport, cache=None, mode="legacy", read_timeout_seconds=timeout,
                          client_info=types.Implementation(name="mcpiranha", version=__version__),
                          **recorder.callbacks()) as client:  # fmt: skip
            raw_prompts = await _all_pages(lambda c: client.list_prompts(cursor=c), "prompts")
            result.prompts = [PromptDef.model_validate(_wire(p)) for p in raw_prompts]
            raw = await _all_pages(lambda c: client.list_resources(cursor=c), "resources")
            result.resources = [ResourceDef.model_validate(_wire(r)) for r in raw]
            await _fetch_content(client, result, timeout=min(timeout, CONTENT_TIMEOUT))
            await anyio.sleep(0.3)  # notifications sent just before the last answer
    return result


async def enumerate_server(
    transport: Transport,
    *,
    timeout: float = 60.0,
    observe_seconds: float = 1.0,
    handshake: Handshake = "auto",
    invoke: tuple[str, ...] = (),
    invoke_args: dict[str, Any] | None = None,
    fuzz: bool = False,
    phase_changed: Callable[[str], None] | None = None,
    probe_changed: Callable[[ProbeRun, bool], Awaitable[None]] | None = None,
) -> Enumeration:
    """`handshake`: "auto" probes the 2026 `server/discover` first and falls back by itself on
    servers that answer with an error; "legacy" sends the classic `initialize`, for older servers
    that crash on the probe instead."""
    notifications: list[str] = []
    result = Enumeration()
    invocation_started = False

    async def on_message(message: Any) -> None:
        if isinstance(message, types.ToolListChangedNotification):
            notifications.append("notifications/tools/list_changed")

    recorder = _Recorder(result)

    try:
        with anyio.fail_after(timeout):
            async with Client(
                transport,
                cache=None,  # rug-pull detection needs every listing fresh from the server
                mode=handshake,
                message_handler=on_message,
                read_timeout_seconds=timeout,
                **recorder.callbacks(),
                client_info=types.Implementation(name="mcpiranha", version=__version__),
            ) as client:
                if phase_changed:
                    phase_changed("listing")
                info: dict[str, Any] = _wire(client.server_info) if client.server_info else {}
                info.setdefault("name", "")
                if client.instructions:
                    info["instructions"] = client.instructions
                info["capabilities"] = _wire(client.server_capabilities)
                result.server_info = ServerInfo.model_validate(info)
                result.protocol_version = client.protocol_version

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

                await _fetch_content(client, result, timeout=min(timeout, CONTENT_TIMEOUT))
                if invoke:
                    invocation_started = True
                    if phase_changed:
                        phase_changed("invocation")
                    recorder.phase = "invocation"
                    available = {t.name: t for t in result.tools}
                    calls = 0
                    for name in dict.fromkeys(invoke):
                        try:
                            if name not in available:
                                raise ValueError("requested tool was not listed")
                            generated = cases(available[name], invoke_args, fuzz)
                            await baseline(available[name].input_schema, generated[0].arguments)
                            for case in generated:
                                if calls >= MAX_CALLS:
                                    raise ValueError("per-server invocation cap reached")
                                calls += 1
                                probe = ProbeRun(
                                    id=f"{name}:{calls}",
                                    tool=name,
                                    variant=case.variant,
                                    argument_path=case.argument_path,
                                    started_at=datetime.now(UTC),
                                    schema_valid=True if case.variant == "baseline" else None,
                                )
                                result.probes.append(probe)
                                recorder.probe_id = probe.id
                                window_started = False
                                try:
                                    if probe_changed:
                                        await probe_changed(probe, True)
                                    window_started = True
                                    with anyio.fail_after(min(timeout, CONTENT_TIMEOUT)):
                                        output = await client.call_tool(name, case.arguments)
                                    text = _content_text(output.content)
                                    if getattr(output, "structured_content", None):
                                        text += "\n" + json.dumps(output.structured_content)
                                    if len(text) > MAX_CONTENT_CHARS:
                                        result.observations.append(
                                            DynamicObservation(
                                                kind="probe_error",
                                                phase="invocation",
                                                tool=name,
                                                probe_id=probe.id,
                                                detail=f"{name}: tool output truncated",
                                            )
                                        )
                                    recorder.keep("tool", name, text)
                                    probe.result_error = bool(getattr(output, "is_error", False))
                                    probe.status = "completed"
                                    if case.variant == "baseline" and probe.result_error:
                                        result.observations.append(
                                            DynamicObservation(
                                                kind="probe_error",
                                                phase="invocation",
                                                tool=name,
                                                probe_id=probe.id,
                                                detail=f"{name}: baseline rejected; probes stopped",
                                            )
                                        )
                                        break
                                except Exception:
                                    probe.status = "error"
                                    raise
                                except BaseException:
                                    probe.status = "interrupted"
                                    raise
                                finally:
                                    with anyio.CancelScope(shield=True):
                                        probe.finished_at = (
                                            datetime.now(UTC) if window_started else None
                                        )
                                        if probe_changed and window_started:
                                            try:
                                                await probe_changed(probe, False)
                                            except Exception as exc:
                                                probe.finished_at = None
                                                result.observations.append(
                                                    DynamicObservation(
                                                        kind="probe_error",
                                                        phase="invocation",
                                                        tool=name,
                                                        probe_id=probe.id,
                                                        detail=f"clock failed: {_short(str(exc))}",
                                                    )
                                                )
                                        recorder.probe_id = None

                        except Exception as exc:
                            result.observations.append(
                                DynamicObservation(
                                    kind="probe_error",
                                    phase="invocation",
                                    detail=f"{name}: {type(exc).__name__}: {_short(str(exc))}",
                                )
                            )
                    recorder.phase = "listing"
                    if phase_changed:
                        phase_changed("listing")
                await anyio.sleep(observe_seconds)
                first, result.tools = result.tools, await tools()
                changes = _tool_changes(first, result.tools)
                latest = {t.name: t for t in result.tools}
                result.earlier_tools = [t for t in first if latest.get(t.name) != t]
    except TimeoutError as exc:
        if invocation_started:
            result.observations.append(
                DynamicObservation(
                    kind="probe_error",
                    phase="invocation",
                    detail="behavioral scan deadline exceeded",
                )
            )
            return result
        raise EnumerationError(f"no complete answer within {timeout:.0f}s") from exc
    except Exception as exc:
        cause = _root_cause(exc)
        if invocation_started:
            result.observations.append(
                DynamicObservation(
                    kind="probe_error",
                    phase="invocation",
                    detail=f"behavioral scan interrupted: {type(cause).__name__}: "
                    f"{_short(str(cause))}",
                )
            )
            return result
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

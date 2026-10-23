"""`--connect`: start (or reach) each server and fill its snapshot with what it really serves."""

from __future__ import annotations

import os
import tempfile
from collections.abc import Callable, Mapping, Sequence
from dataclasses import dataclass

import anyio

from mcpiranha.acquire.listing import (
    Enumeration,
    EnumerationError,
    enumerate_server,
    observe_classic,
)
from mcpiranha.acquire.oauth import OAuthError, OpenUrl
from mcpiranha.acquire.sandbox import Prepared, Sandbox, SandboxError, prepare
from mcpiranha.core.models import DynamicObservation, ServerSnapshot
from mcpiranha.core.secrets import mask_secrets

ProgressFn = Callable[[ServerSnapshot, str], None]
_STDERR_TAIL = 300


@dataclass(frozen=True, slots=True)
class ConnectOptions:
    sandbox: Sandbox = "docker"
    real_credentials: bool = False
    timeout: float = 60.0
    observe_seconds: float = 1.0
    jobs: int = 4  # servers connected to at the same time
    extra_headers: Mapping[str, str] | None = None  # --header, for a single URL target
    oauth_open: OpenUrl | None = None  # --oauth: opens the sign-in URL (a browser, normally)
    allow_network: bool = False  # sandboxed servers may use the network while running
    allow_install_scripts: bool = False  # npm install scripts and PyPI source builds may run


def _auth_hint(snapshot: ServerSnapshot, options: ConnectOptions, message: str,
               statuses: Sequence[int]) -> str:  # fmt: skip
    denied = {401, 403} & set(statuses)
    if not denied and not any(s in message for s in ("401", "403", "Unauthorized", "Forbidden")):
        return ""
    if snapshot.launch and snapshot.launch.headers and not options.real_credentials:
        return " It requires authentication: rerun with --real-credentials to send its headers."
    if options.oauth_open is None:
        return (
            " It requires authentication: rerun with --oauth to sign in, or pass a token with "
            "--header."
        )
    return " It requires authentication, and signing in didn't succeed."


async def _enumerate_with_fallback(prepared: Prepared, options: ConnectOptions) -> Enumeration:
    """Try the SDK's default handshake, then the classic one in a fresh connection: some older
    servers crash on the 2026 `server/discover` probe instead of rejecting it."""
    try:
        return await enumerate_server(prepared.connect(), timeout=options.timeout,
                                      observe_seconds=options.observe_seconds)  # fmt: skip
    except EnumerationError as first:
        if {401, 403} & set(prepared.http_statuses):
            raise  # an auth failure won't go away with another handshake
        try:
            return await enumerate_server(prepared.connect(), timeout=options.timeout,
                                          observe_seconds=options.observe_seconds,
                                          handshake="legacy")  # fmt: skip
        except EnumerationError as second:
            raise EnumerationError(f"{second} (also failed with the 2026 handshake: {first})"
                                   ) from second  # fmt: skip


CLASSIC_UNTIL = "2026-07-28"  # the first protocol version without mid-request server requests


async def _observe_classic(prepared: Prepared, options: ConnectOptions, found: Enumeration) -> None:
    """A second, classic-protocol session to see what the server sends clients that allow it
    (sampling, elicitation, roots, logs). Best effort: a server that won't speak it is fine."""
    try:
        extra = await observe_classic(prepared.connect(), timeout=options.timeout)
    except Exception:  # the main listing already succeeded
        return
    seen = {(c.kind, c.ref, c.text) for c in found.content}
    found.content += [c for c in extra.content if (c.kind, c.ref, c.text) not in seen]
    found.observations += extra.observations


async def connect_one(
    snapshot: ServerSnapshot,
    options: ConnectOptions,
    progress: ProgressFn | None = None,
    environ: Mapping[str, str] | None = None,
) -> ServerSnapshot:
    """The snapshot with tools, prompts, resources and observations filled in."""
    if snapshot.launch is None:
        raise SandboxError("no launch configuration")
    with tempfile.TemporaryFile("w+", encoding="utf-8", errors="replace") as errlog:
        prepared = await prepare(
            snapshot.launch,
            sandbox=options.sandbox,
            real_credentials=options.real_credentials,
            errlog=errlog,
            environ=os.environ if environ is None else environ,
            extra_headers=options.extra_headers,
            oauth_open=options.oauth_open,
            allow_network=options.allow_network,
            allow_install_scripts=options.allow_install_scripts,
        )
        if progress:
            progress(snapshot, f"connecting ({prepared.label})")
        try:
            found = await _enumerate_with_fallback(prepared, options)
            if found.protocol_version >= CLASSIC_UNTIL and (found.prompts or found.resources):
                await _observe_classic(prepared, options, found)
        except EnumerationError as exc:
            errlog.flush()
            errlog.seek(0)
            tail = mask_secrets(errlog.read()[-_STDERR_TAIL:].strip())
            message = str(exc) + _auth_hint(snapshot, options, str(exc), prepared.http_statuses)
            raise EnumerationError(message + (f" Server stderr: {tail}" if tail else "")) from exc
        finally:
            await prepared.cleanup()

    observations = [*snapshot.observations, *found.observations]
    if prepared.remote and not prepared.sent_credentials:
        observations.append(
            DynamicObservation(
                kind="auth_not_required",
                phase="listing",
                detail=f"listed {len(found.tools)} tool(s) without sending any credentials",
            )
        )
    return snapshot.model_copy(
        update={
            "server_info": found.server_info,
            "tools": found.tools,
            "earlier_tools": found.earlier_tools,
            "prompts": found.prompts,
            "resources": found.resources,
            "observations": observations,
            "content": found.content,
            "tools_listed": True,
            "package": prepared.resolved or snapshot.package,
        }
    )


async def connect_all(
    snapshots: Sequence[ServerSnapshot],
    options: ConnectOptions,
    progress: ProgressFn | None = None,
) -> tuple[list[ServerSnapshot], list[str]]:
    """Connect to every server that hasn't been listed yet, `options.jobs` at a time. Results
    keep the input order. A server that fails keeps its config-only snapshot and produces a
    warning; it doesn't stop the scan. Servers disabled in their client config are skipped."""
    results: list[ServerSnapshot] = list(snapshots)
    warnings: dict[int, str] = {}
    limiter = anyio.CapacityLimiter(max(1, options.jobs))

    async def one(i: int, snapshot: ServerSnapshot) -> None:
        async with limiter:
            try:
                listed = await connect_one(snapshot, options, progress)
            except Exception as exc:  # any failure is this server's problem, not the scan's
                known = isinstance(exc, (SandboxError, EnumerationError, OAuthError))
                warnings[i] = f"could not list {snapshot.name!r}: " + (
                    str(exc) if known else f"{type(exc).__name__}: {exc}"
                )
                if progress:
                    progress(snapshot, "failed")
                return
        if progress:
            progress(snapshot, f"listed {len(listed.tools)} tool(s), {len(listed.prompts)} "
                     f"prompt(s), {len(listed.resources)} resource(s)")  # fmt: skip
        results[i] = listed

    async with anyio.create_task_group() as group:
        for i, snapshot in enumerate(snapshots):
            if snapshot.tools_listed or snapshot.launch is None:
                continue
            if snapshot.client_settings and snapshot.client_settings.disabled:
                if progress:
                    progress(snapshot, "skipped: disabled in its client config")
                continue
            group.start_soon(one, i, snapshot)
    return results, [warnings[i] for i in sorted(warnings)]

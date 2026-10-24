"""Normalize trusted strace events, resolve file paths, and correlate bounded call windows."""

from __future__ import annotations

import ast
import ipaddress
import posixpath
import re
from datetime import UTC, datetime
from typing import Literal
from urllib.parse import urlsplit

from mcpiranha.core.models import DynamicObservation, ProbeRun
from mcpiranha.dynamic.files import FileTracker, number

Phase = Literal["startup", "listing", "invocation"]
MAX_EVENTS = 2000
_STRING = r'"(?:\\.|[^"\\])*"'
_LINE = re.compile(r"^\s*(?:(?:\[pid\s+)?(\d+)\]?\s+)?(\d{10,}\.\d+)\s+(.*)")


def destination(value: str) -> str:
    """Normalize exact host:port policy entries; no globs, URLs, userinfo, or implicit ports."""
    parsed = urlsplit("//" + value)
    if (
        not parsed.hostname
        or not parsed.port
        or parsed.username
        or parsed.password
        or parsed.path
        or parsed.query
        or parsed.fragment
        or any(c.isspace() for c in value)
    ):
        raise ValueError("destination must be an exact host:port (bracket IPv6 addresses)")
    host = parsed.hostname.rstrip(".").lower()
    try:
        address = ipaddress.ip_address(host)
        host = f"[{address}]" if address.version == 6 else str(address)
    except ValueError:
        if not re.fullmatch(r"[a-z0-9.-]+", host):
            raise ValueError("invalid destination hostname") from None
    return f"{host}:{parsed.port}"


def _text(quoted: str) -> str:
    try:
        value: object = ast.literal_eval(quoted)
        return value if isinstance(value, str) else ""
    except (ValueError, SyntaxError):
        return ""


def _network(body: str) -> str | None:
    port = re.search(r"(?:sin6?_port)=htons\((\d+)\)", body)
    host = re.search(r'(?:inet_addr\(|inet_pton\(AF_INET6, )"([^" ]+)"', body)
    if port and host:
        return destination(f"[{host[1]}]:{port[1]}" if ":" in host[1] else f"{host[1]}:{port[1]}")
    return None


def _dns(strings: list[str]) -> str | None:
    for quoted in strings:
        try:
            packet = _text(quoted).encode("latin1")
        except UnicodeEncodeError:
            continue
        if len(packet) < 17 or packet[2] & 0x80 or packet[4:6] != b"\x00\x01":
            continue
        labels: list[str] = []
        offset = 12
        while offset < len(packet) and len(labels) < 127:
            size = packet[offset]
            offset += 1
            if size == 0:
                return ".".join(labels).lower() if labels else None
            if size > 63 or offset + size > len(packet):
                break
            label = packet[offset : offset + size].decode("ascii", errors="replace")
            if not re.fullmatch(r"[a-zA-Z0-9_-]+", label):
                break
            labels.append(label)
            offset += size
    return None


def _records(trace: str) -> tuple[list[tuple[str, float, str]], dict[str, tuple[float, str]]]:
    records: list[tuple[str, float, str]] = []
    pending: dict[str, tuple[float, str]] = {}
    for line in trace.splitlines():
        match = _LINE.match(line)
        if not match:
            continue
        pid, timestamp, body = match[1] or "1", float(match[2]), match[3]
        if body.endswith("<unfinished ...>"):
            pending[pid] = (timestamp, body.removesuffix("<unfinished ...>"))
            continue
        resumed = re.match(r"<\.\.\. \w+ resumed>(.*)", body)
        if resumed:
            if pid not in pending:
                continue
            timestamp, prefix = pending.pop(pid)
            body = prefix + resumed[1]
        records.append((pid, timestamp, body))
    # Children can run before the parent's clone return is printed. Apply successful
    # mutations by syscall start time after assembling split records, preserving ties.
    records.sort(key=lambda record: record[1])
    return records, pending


def observations(
    trace: str,
    boundaries: list[tuple[float, Phase]],
    *,
    cwd: str = "/tmp",
    expected_destinations: tuple[str, ...] = (),
    proxy_destination: str | None = None,
    protected_pids: set[str] | None = None,
) -> list[DynamicObservation]:
    result: list[DynamicObservation] = []
    working: dict[str, list[str]] = {}
    sockets: dict[tuple[str, str], str] = {}
    expected = {destination(v) for v in expected_destinations}
    files = FileTracker()
    records, pending = _records(trace)
    for pid, timestamp, body in records:
        phase: Phase = "startup"
        for at, name in boundaries:
            if at <= timestamp:
                phase = name
        current = working.setdefault(pid, [cwd])
        returned = re.search(
            r"\)\s+=\s+(-?(?:0x[0-9a-fA-F]+|\d+))(?:<([^>]+)>)?(?: [A-Z][A-Z0-9_]+(?: \(.*\))?)?$",
            body,
        )
        value = number(returned[1]) if returned else None
        success = value >= 0 if value is not None else None
        operation = body.split("(", 1)[0]
        if operation == "close" and success and (closed := re.match(r"close\((\d+)", body)):
            sockets.pop((pid, closed[1]), None)
        arguments_body = body[: returned.start()] if returned else body
        strings = re.findall(_STRING, arguments_body)
        if operation in ("clone", "clone3", "fork", "vfork") and returned and success:
            working[returned[1]] = current if "CLONE_FS" in body else [current[0]]
        if operation == "unshare" and success and "CLONE_FS" in body:
            working[pid] = current = [current[0]]
        if operation in ("chdir", "fchdir") and success:
            changed = (_text(strings[0]) if strings else "") if operation == "chdir" else ""
            if operation == "fchdir" and (directory := re.search(r"\d+<([^>]+)>", body)):
                changed = directory[1]
            if changed:
                current[0] = posixpath.normpath(posixpath.join(current[0], changed))
        kind: (
            Literal[
                "file_open",
                "file_access",
                "file_alias",
                "process_spawn",
                "net_connect",
                "dns_lookup",
                "trace_tamper",
            ]
            | None
        ) = None
        path = None
        readable = None
        target = None
        file_event = files.observe(
            pid, operation, body, current[0], value, returned[2] if returned else None
        )
        if file_event:
            kind = file_event.kind
            path, readable = file_event.path, file_event.readable
        elif operation in ("execve", "execveat"):
            kind = "process_spawn"
        elif operation in ("connect", "sendto", "sendmsg", "sendmmsg"):
            descriptor = re.match(r"\w+\((\d+)", body)
            target = _network(body)
            if descriptor:
                if operation == "connect":
                    sockets.pop((pid, descriptor[1]), None)
                    if target:
                        sockets[pid, descriptor[1]] = target
                elif target is None:
                    target = sockets.get((pid, descriptor[1]))
            if target and target.endswith(":53") and operation != "connect":
                query = _dns(strings)
                if query:
                    target = f"{query}:53"
            if target or "AF_INET" in body:
                kind = "dns_lookup" if target and target.endswith(":53") else "net_connect"
        interference = re.match(r"(?:kill\((\d+),|ptrace\(PTRACE_\w+, (\d+),)", body)
        target_pid = next((v for v in interference.groups() if v), None) if interference else None
        if protected_pids and target_pid in protected_pids:
            kind = "trace_tamper"
        if kind:
            result.append(
                DynamicObservation(
                    kind=kind,
                    phase=phase,
                    detail=body[:2500],
                    at=datetime.fromtimestamp(timestamp, UTC),
                    path=path,
                    success=success,
                    readable=readable,
                    syscall=operation,
                    honeytoken=file_event.token if file_event else None,
                    byte_count=file_event.byte_count if file_event else None,
                    destination=target,
                    expected=target in expected if target else False,
                    infrastructure=target is not None
                    and (
                        target == proxy_destination
                        or target == "mcpiranha-egress:53"
                        or (target == "127.0.0.11:53" and operation == "connect")
                    ),
                )
            )
        if len(result) >= MAX_EVENTS:
            result.append(
                DynamicObservation(
                    kind="probe_error", phase=phase, detail="trace observation cap reached"
                )
            )
            break
    if pending:
        result.append(
            DynamicObservation(
                kind="probe_error", phase="listing", detail="incomplete syscall records in trace"
            )
        )
    return result


def correlate(events: list[DynamicObservation], probes: list[ProbeRun]) -> list[DynamicObservation]:
    """Time correlation is evidence of temporal association, never proof of causality."""
    result: list[DynamicObservation] = []
    for event in events:
        owner = next(
            (
                p
                for p in probes
                if event.at is not None
                and p.started_at <= event.at
                and (p.finished_at is not None and event.at <= p.finished_at)
            ),
            None,
        )
        result.append(
            event.model_copy(
                update={"probe_id": owner.id, "tool": owner.tool, "phase": "invocation"}
            )
            if owner
            else event
        )
    return result

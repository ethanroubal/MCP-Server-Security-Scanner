"""Track observed descriptors and aliases without reading file contents from the tracee."""

from __future__ import annotations

import ast
import posixpath
import re
from dataclasses import dataclass
from typing import Literal

from mcpiranha.dynamic.constants import CANARY, HONEYTOKENS

QUOTED = r'"(?:\\.|[^"\\])*"'


def number(text: str) -> int:
    if text.strip() in ("~0U", "UINT_MAX"):
        return 0xFFFFFFFF
    matched = re.match(r"\s*(-?(?:0x[0-9a-fA-F]+|\d+))", text)
    return int(matched[1], 16 if "x" in matched[1] else 10) if matched else -1


def arguments(body: str) -> list[str]:
    """Split syscall arguments while respecting strings, nested structures and FD annotations."""
    result: list[str] = []
    text = body[body.find("(") + 1 :]
    start, depth, annotated = 0, 0, False
    quoted = escaped = False
    for index, char in enumerate(text):
        if quoted:
            if escaped:
                escaped = False
            elif char == "\\":
                escaped = True
            elif char == '"':
                quoted = False
        elif char == '"':
            quoted = True
        elif annotated:
            if char == ">" and (index == 0 or text[index - 1] != "-"):
                annotated = False
        elif char == "<":
            annotated = True
        elif char in "[{(":
            depth += 1
        elif char in "]})":
            if char == ")" and depth == 0:
                result.append(text[start:index].strip())
                break
            depth -= 1
        elif char == "," and depth == 0:
            result.append(text[start:index].strip())
            start = index + 1
    return result


def path_argument(text: str, cwd: str, directory: str | None = None) -> str | None:
    matched = re.match(QUOTED, text)
    if not matched:
        return None
    try:
        decoded: object = ast.literal_eval(matched[0])
    except (ValueError, SyntaxError):
        return None
    if not isinstance(decoded, str):
        return None
    base = cwd
    if directory and (annotation := re.search(r"<([^>]+)>", directory)):
        base = annotation[1]
    return posixpath.normpath(posixpath.join(base, decoded))


@dataclass(frozen=True)
class Descriptor:
    path: str
    token: str | None
    cloexec: bool = False


@dataclass(frozen=True)
class FileEvent:
    kind: Literal["file_open", "file_alias", "file_access"]
    path: str
    token: str | None
    readable: bool = True
    byte_count: int | None = None


class FileTracker:
    def __init__(self) -> None:
        self.tables: dict[str, dict[int, Descriptor]] = {}
        self.aliases: dict[str, str] = {path: path for path in (*HONEYTOKENS, CANARY)}

    def observe(
        self,
        pid: str,
        operation: str,
        body: str,
        cwd: str,
        returned: int | None,
        returned_path: str | None,
    ) -> FileEvent | None:
        args = arguments(body)
        table = self.tables.setdefault(pid, {})
        success = returned is not None and returned >= 0
        if operation in ("clone", "clone3", "fork", "vfork") and success:
            self.tables[str(returned)] = table if "CLONE_FILES" in body else dict(table)
        if operation == "unshare" and success and "CLONE_FILES" in body:
            self.tables[pid] = table = dict(table)
        if operation in ("execve", "execveat") and success:
            self.tables[pid] = table = {fd: item for fd, item in table.items() if not item.cloexec}
        if operation == "close" and success and args:
            table.pop(number(args[0]), None)
        if operation == "close_range" and success and len(args) >= 2:
            if "CLOSE_RANGE_UNSHARE" in body:
                self.tables[pid] = table = dict(table)
            first, last = number(args[0]), number(args[1])
            if first >= 0 and last >= 0:
                for fd in list(table):
                    if first <= fd <= last:
                        if "CLOSE_RANGE_CLOEXEC" in body:
                            item = table[fd]
                            table[fd] = Descriptor(item.path, item.token, True)
                        else:
                            del table[fd]
        if operation in ("dup", "dup2", "dup3", "fcntl") and success and args:
            source = table.get(number(args[0]))
            if operation == "fcntl" and len(args) > 1 and "F_DUPFD" not in args[1]:
                if source and len(args) > 2 and "F_SETFD" in args[1]:
                    descriptor = number(args[0])
                    if descriptor >= 0:
                        table[descriptor] = Descriptor(
                            source.path, source.token, "FD_CLOEXEC" in args[2]
                        )
            elif returned is not None:
                if operation == "dup2" and returned == number(args[0]):
                    return None
                if source:
                    table[returned] = Descriptor(
                        source.path,
                        source.token,
                        (operation == "dup3" and len(args) > 2 and "O_CLOEXEC" in args[2])
                        or (operation == "fcntl" and "F_DUPFD_CLOEXEC" in args[1]),
                    )
                else:
                    table.pop(returned, None)
        if operation in ("open", "openat", "openat2") and args:
            path = (
                returned_path
                if success and returned_path
                else path_argument(
                    args[0] if operation == "open" else args[1],
                    cwd,
                    args[0] if operation != "open" else None,
                )
            )
            if path:
                path = posixpath.normpath(path)
                flags = args[1] if operation == "open" else args[2]
                readable = re.search(r"\b(?:O_WRONLY|O_PATH)\b", flags) is None
                requested = path_argument(
                    args[0] if operation == "open" else args[1],
                    cwd,
                    args[0] if operation != "open" else None,
                )
                token = self.aliases.get(path) or self.aliases.get(requested or "")
                if success and returned is not None:
                    table[returned] = Descriptor(path, token, "O_CLOEXEC" in flags)
                return FileEvent("file_open", path, token, readable)
        if operation in ("link", "linkat", "rename", "renameat", "renameat2") and success:
            descriptor_token = None
            if operation in ("link", "rename") and len(args) >= 2:
                old, new = path_argument(args[0], cwd), path_argument(args[1], cwd)
            elif len(args) >= 4:
                old = path_argument(args[1], cwd, args[0])
                if args[1] == '""' and "AT_EMPTY_PATH" in body:
                    source = table.get(number(args[0]))
                    old = source.path if source else None
                    descriptor_token = source.token if source else None
                new = path_argument(args[3], cwd, args[2])
            else:
                old = new = None
            if old and new:
                affected = {
                    key: token
                    for key, token in self.aliases.items()
                    if key == old or key.startswith(old + "/")
                }
                if descriptor_token:
                    affected[old] = descriptor_token
                replaced = {
                    key: token
                    for key, token in self.aliases.items()
                    if key == new or key.startswith(new + "/")
                }
                if operation.startswith("rename"):
                    for key in (*affected, *replaced):
                        self.aliases.pop(key, None)
                else:
                    self.aliases.pop(new, None)
                for key, token in affected.items():
                    self.aliases[new + key[len(old) :]] = token
                if "RENAME_EXCHANGE" in body:
                    for key, token in replaced.items():
                        self.aliases[old + key[len(new) :]] = token
                if affected:
                    key = sorted(affected)[0]
                    return FileEvent("file_alias", new + key[len(old) :], affected[key], False)
        if operation in ("unlink", "unlinkat") and success and args:
            path = path_argument(
                args[0] if operation == "unlink" else args[1],
                cwd,
                args[0] if operation == "unlinkat" else None,
            )
            if path:
                self.aliases.pop(path, None)
        if operation in ("read", "pread64", "readv", "preadv", "preadv2") and args:
            item = table.get(number(args[0]))
            if item and item.token and returned is not None and returned > 0:
                return FileEvent("file_access", item.path, item.token, True, returned)
        if operation == "mmap" and success and len(args) >= 5 and "PROT_READ" in args[2]:
            descriptor = number(args[4])
            item = table.get(descriptor)
            if item and item.token and "MAP_ANONYMOUS" not in args[3]:
                return FileEvent("file_access", item.path, item.token)
        return None

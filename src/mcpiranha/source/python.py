"""Python source analysis with the standard library's `ast` (the code is parsed, never run)."""

from __future__ import annotations

import ast
from collections.abc import Iterator

from mcpiranha.core.models import SourceHit, SourceHitKind
from mcpiranha.source import patterns

# Calls whose result is code someone hid or fetched: decoded, decompressed or downloaded.
_DECODERS = frozenset({"b64decode", "b32decode", "b85decode", "a85decode", "urlsafe_b64decode",
                       "decodebytes", "decompress", "fromhex", "unhexlify", "urlopen", "get",
                       "post", "request", "read_text", "rot13"})  # fmt: skip
_RUNNERS = frozenset({"exec", "eval", "compile"})


def _name(node: ast.AST) -> str:
    """`a.b.c` for a Name/Attribute chain, else ""."""
    if isinstance(node, ast.Name):
        return node.id
    if isinstance(node, ast.Attribute):
        base = _name(node.value)
        return f"{base}.{node.attr}" if base else node.attr
    return ""


def _is_environ(node: ast.AST) -> bool:
    """os.environ, os.environ.items()/keys()/values()/copy(), dict(os.environ)."""
    if _name(node) in ("os.environ", "environ"):
        return True
    if isinstance(node, ast.Call):
        func = node.func
        if isinstance(func, ast.Attribute) and func.attr in ("items", "keys", "values", "copy"):
            return _is_environ(func.value)
        if _name(func) == "dict" and node.args:
            return _is_environ(node.args[0])
    return False


def _reads_values(node: ast.AST, iters: list[ast.AST]) -> bool:
    """os.environ.items()/.values() is iterated, or os.environ[...] / .get() is read inside."""
    for i in iters:
        if (
            isinstance(i, ast.Call)
            and isinstance(i.func, ast.Attribute)
            and i.func.attr in ("items", "values")
        ):
            return True
    for child in ast.walk(node):
        if isinstance(child, ast.Subscript) and _name(child.value) in ("os.environ", "environ"):
            return True
        if isinstance(child, ast.Call) and _name(child.func) in (
            "os.environ.get",
            "environ.get",
            "os.getenv",
            "getenv",
        ):
            return True
    return False


def _strings(node: ast.AST) -> Iterator[str]:
    for child in ast.walk(node):
        if isinstance(child, ast.Constant) and isinstance(child.value, str):
            yield child.value


class _Visitor(ast.NodeVisitor):
    def __init__(self, path: str, lines: list[str], tree: ast.AST) -> None:
        self.path, self.lines = path, lines
        self.hits: list[SourceHit] = []
        self.parents: dict[ast.AST, ast.AST] = {
            child: node for node in ast.walk(tree) for child in ast.iter_child_nodes(node)
        }
        self.written = _written_names(tree)
        self.executed = _names_passed_to(tree, patterns.EXEC_CALLS)
        self.sets_approval = bool(patterns.APPROVE_SETTING.search("\n".join(lines)))

    def hit(self, node: ast.AST, kind: SourceHitKind, detail: str) -> None:
        line = getattr(node, "lineno", 1)
        code = self.lines[line - 1].strip() if 0 < line <= len(self.lines) else ""
        self.hits.append(SourceHit(kind=kind, file=self.path, line=line, code=code[:200],
                                   detail=detail))  # fmt: skip

    # --- hardcoded recipients ---
    def visit_Dict(self, node: ast.Dict) -> None:
        for key, value in zip(node.keys, node.values, strict=True):
            if (isinstance(key, ast.Constant) and isinstance(key.value, str)
                    and isinstance(value, ast.Constant) and isinstance(value.value, str)
                    and patterns.recipient(key.value, value.value)):  # fmt: skip
                self.hit(node, "hardcoded_recipient", f"{key.value}: {value.value}")
        self.generic_visit(node)

    def visit_Call(self, node: ast.Call) -> None:
        for kw in node.keywords:
            if (kw.arg and isinstance(kw.value, ast.Constant) and isinstance(kw.value.value, str)
                    and patterns.recipient(kw.arg, kw.value.value)):  # fmt: skip
                self.hit(node, "hardcoded_recipient", f"{kw.arg}={kw.value.value}")
        func = _name(node.func)
        short = func.rsplit(".", 1)[-1]
        # the whole environment, serialized: json.dumps(os.environ), str(dict(os.environ))
        if short in ("dumps", "dump", "str", "repr", "urlencode") and any(
            _is_environ(a) for a in node.args
        ):
            self.hit(node, "env_harvest", f"serializes the environment with {func}()")
        if short in _RUNNERS and node.args:
            inner = {_name(c.func).rsplit(".", 1)[-1] for c in ast.walk(node.args[0])
                     if isinstance(c, ast.Call)}  # fmt: skip
            if found := sorted(inner & (_DECODERS | {"loads"})):  # + marshal.loads
                self.hit(node, "dynamic_code", f"{short}() of the result of {', '.join(found)}()")
        # a socket wired to stdin/stdout: os.dup2(s.fileno(), 0)
        if func in ("os.dup2", "dup2") and node.args and "fileno" in ast.dump(node.args[0]):
            self.hit(node, "reverse_shell", "connects a socket to the process's stdin/stdout")
        # rmtree / rm of the home directory or the filesystem root
        if (
            short in ("rmtree", "rmdir", "unlink", "remove")
            and node.args
            and _is_home_or_root(node.args[0])
        ):
            self.hit(node, "destructive", f"{func}() of the home directory or /")
        if func in ("pyarmor_runtime", "__pyarmor__") or func.endswith(".__pyarmor__"):
            self.hit(node, "obfuscated", "PyArmor-obfuscated code (can't be reviewed)")
        self.generic_visit(node)

    def in_call(self, node: ast.AST, calls: frozenset[str]) -> bool:
        """The literal is an argument (a few levels down) of one of `calls`, or bound to a name
        that's passed to one."""
        current = node
        for _ in range(5):
            parent = self.parents.get(current)
            if parent is None:
                return False
            current = parent
            if isinstance(current, ast.Call) and _name(current.func).rsplit(".", 1)[-1] in calls:
                return True
            if isinstance(current, ast.Assign):
                return any(isinstance(t, ast.Name) and t.id in self.executed
                           for t in current.targets)  # fmt: skip
        return False

    def in_write(self, node: ast.AST) -> bool:
        """The literal is part of a call that writes a file (a few levels up)."""
        current = node
        for _ in range(7):
            parent = self.parents.get(current)
            if parent is None:
                return False
            current = parent
            if isinstance(current, ast.Call) and _writes(current):
                return True
            if isinstance(current, ast.Assign):  # bound to a name: is that name written?
                return any(isinstance(t, ast.Name) and t.id in self.written
                           for t in current.targets)  # fmt: skip
        return False

    def visit_Assign(self, node: ast.Assign) -> None:
        value = node.value
        for target in node.targets:
            if (isinstance(target, ast.Subscript) and isinstance(target.slice, ast.Constant)
                    and isinstance(target.slice.value, str) and isinstance(value, ast.Constant)
                    and isinstance(value.value, str)
                    and patterns.recipient(target.slice.value, value.value)):  # fmt: skip
                self.hit(node, "hardcoded_recipient", f"{target.slice.value} = {value.value}")
        self.generic_visit(node)

    # --- collecting secret-looking variables ---
    def _env_loop(self, node: ast.AST, iters: list[ast.AST]) -> None:
        # Values, not just names: listing which TOKEN variables exist is a diagnostic.
        if any(_is_environ(i) for i in iters) and _reads_values(node, iters):
            words = sorted({m.group(0).lower() for s in _strings(node)
                            if (m := patterns.SECRET_WORDS.search(s))})  # fmt: skip
            if words:
                detail = f"collects environment variables named like {', '.join(words)}"
                self.hit(node, "env_harvest", detail)

    def visit_DictComp(self, node: ast.DictComp) -> None:
        self._env_loop(node, [g.iter for g in node.generators])
        self.generic_visit(node)

    def visit_ListComp(self, node: ast.ListComp) -> None:
        self._env_loop(node, [g.iter for g in node.generators])
        self.generic_visit(node)

    def visit_SetComp(self, node: ast.SetComp) -> None:
        self._env_loop(node, [g.iter for g in node.generators])
        self.generic_visit(node)

    def visit_GeneratorExp(self, node: ast.GeneratorExp) -> None:
        self._env_loop(node, [g.iter for g in node.generators])
        self.generic_visit(node)

    def visit_For(self, node: ast.For) -> None:
        self._env_loop(node, [node.iter])
        self.generic_visit(node)

    # --- strings: credential paths, exfiltration hosts, shells, miners, persistence ---
    def visit_Constant(self, node: ast.Constant) -> None:
        if isinstance(node.value, str):
            self.string(node, node.value)

    def visit_JoinedStr(self, node: ast.JoinedStr) -> None:
        text = "".join(v.value if isinstance(v, ast.Constant) and isinstance(v.value, str)
                       else "{}" for v in node.values)  # fmt: skip
        self.string(node, text)
        for value in node.values:  # the literal parts were judged together
            if not isinstance(value, ast.Constant):
                self.visit(value)

    def string(self, node: ast.AST, text: str) -> None:
        for kind, detail in patterns.string_hits(text):
            if kind not in patterns.NEEDS_EXEC or self.in_call(node, patterns.EXEC_CALLS):
                self.hit(node, kind, detail)
        if (found := patterns.written_path_kind(text)) and self.in_write(node):
            kind, detail = found
            if kind == "client_config" and self.sets_approval:
                detail += ", in code that sets auto-approve"
            self.hit(node, kind, detail)


def _writes(call: ast.Call) -> bool:
    short = _name(call.func).rsplit(".", 1)[-1]
    if short not in patterns.WRITE_CALLS:
        return False
    if short != "open":
        return True
    modes = [a for a in call.args[1:2] if isinstance(a, ast.Constant)] + [
        k.value for k in call.keywords if k.arg == "mode" and isinstance(k.value, ast.Constant)
    ]
    if isinstance(call.func, ast.Attribute):  # Path.open("a"): the mode is the first argument
        modes = [a for a in call.args[:1] if isinstance(a, ast.Constant)] + modes
    return any(isinstance(m.value, str) and patterns.WRITE_MODES.search(m.value) for m in modes)


def _written_names(tree: ast.AST) -> set[str]:
    """Names some call writes to: `p.write_text(...)`, `open(p, "a")`, `shutil.copy(x, p)`."""
    names: set[str] = set()
    for node in ast.walk(tree):
        if not isinstance(node, ast.Call) or not _writes(node):
            continue
        if isinstance(node.func, ast.Attribute) and isinstance(node.func.value, ast.Name):
            names.add(node.func.value.id)
        names.update(a.id for a in node.args if isinstance(a, ast.Name))
    return names


def _names_passed_to(tree: ast.AST, calls: frozenset[str]) -> set[str]:
    return {a.id for node in ast.walk(tree) if isinstance(node, ast.Call)
            and _name(node.func).rsplit(".", 1)[-1] in calls
            for a in node.args if isinstance(a, ast.Name)}  # fmt: skip


def _is_home_or_root(node: ast.AST) -> bool:
    """Path.home(), os.path.expanduser("~"), "~", "/", os.environ["HOME"]."""
    text = ast.dump(node)
    if isinstance(node, ast.Constant):
        return node.value in ("/", "~", "~/", "C:\\")
    return (
        ("attr='home'" in text and "Path" in text)
        or ("expanduser" in text and "Constant(value='~')" in text)
        or "Constant(value='HOME')" in text
    )


def analyze(path: str, text: str) -> list[SourceHit]:
    """Hits in one Python file. Files that don't parse (Python 2, newer syntax) give none."""
    try:
        tree = ast.parse(text, filename=path)
    except (SyntaxError, ValueError):
        return []
    visitor = _Visitor(path, text.splitlines(), tree)
    visitor.visit(tree)
    return visitor.hits

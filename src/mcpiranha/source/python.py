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
    def __init__(self, path: str, lines: list[str]) -> None:
        self.path, self.lines = path, lines
        self.hits: list[SourceHit] = []

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
            if found := sorted(inner & _DECODERS):
                self.hit(node, "dynamic_code", f"{short}() of the result of {', '.join(found)}()")
        self.generic_visit(node)

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

    # --- strings: credential paths, exfiltration hosts, curl | sh ---
    def visit_Constant(self, node: ast.Constant) -> None:
        if isinstance(node.value, str):
            check_string(self, node, node.value)

    def visit_JoinedStr(self, node: ast.JoinedStr) -> None:
        text = "".join(v.value if isinstance(v, ast.Constant) and isinstance(v.value, str)
                       else "{}" for v in node.values)  # fmt: skip
        check_string(self, node, text)


def check_string(visitor: _Visitor, node: ast.AST, text: str) -> None:
    if path := patterns.sensitive_path(text):
        visitor.hit(node, "sensitive_file", f"names {path}")
    if url := patterns.exfil_host(text):
        visitor.hit(node, "exfil_host", f"hardcoded {url}")
    if patterns.HEADER_RECIPIENT.search(text):
        visitor.hit(node, "hardcoded_recipient", "a Bcc/Cc header with a fixed address")


def analyze(path: str, text: str) -> list[SourceHit]:
    """Hits in one Python file. Files that don't parse (Python 2, newer syntax) give none."""
    try:
        tree = ast.parse(text, filename=path)
    except (SyntaxError, ValueError):
        return []
    visitor = _Visitor(path, text.splitlines())
    visitor.visit(tree)
    return visitor.hits

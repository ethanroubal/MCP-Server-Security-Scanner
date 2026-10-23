"""Taint analysis for Python MCP servers: tool arguments that reach a shell, SQL, path or URL.

Tool handlers are found by how servers register them (`@server.tool()`, `server.add_tool(fn)`,
the low-level `@server.call_tool()` and its `arguments` dict). Their parameters are tainted, and
taint follows assignments and calls into functions in the same file (two levels).

What's reported is injection, not capability. Every value gets a shape:

- whole: the argument itself (`exec(command)` in a shell tool, `fetch(url)` in a fetch tool) is
  the tool doing what it says; the toxic-flow rules already account for that. Not reported.
- mixed: the argument spliced into text the developer wrote (`f"git log {branch}"`,
  `"SELECT ... " + name`): the developer meant a fixed command, query or host. Reported.
- based: the argument joined to a base directory (`os.path.join(ROOT, name)`): the developer
  meant to confine it. Reported unless the function checks containment.

Quoting (`shlex.quote`), casts (`int()`) and `os.path.basename` clear taint.
"""

from __future__ import annotations

import ast
import re
from dataclasses import dataclass, field
from typing import Literal

from mcpiranha.core.models import SourceHit, SourceHitKind

Shape = Literal["whole", "mixed", "based"]
_RANK = {"whole": 1, "based": 2, "mixed": 3}
MAX_DEPTH = 2

_SANITIZERS = frozenset({"quote", "shlex.quote", "int", "float", "bool", "basename",
                         "secure_filename", "escape", "escape_string", "quote_plus",
                         "quote_identifier", "len"})  # fmt: skip
_SHELL_CALLS = frozenset({"run", "call", "check_call", "check_output", "Popen"})
_ALWAYS_SHELL = frozenset({"os.system", "system", "os.popen", "popen", "getoutput",
                           "getstatusoutput", "create_subprocess_shell"})  # fmt: skip
_SQL_CALLS = frozenset({"execute", "executemany", "executescript", "raw", "query", "text",
                        "exec_driver_sql", "read_sql", "read_sql_query", "fetch", "fetchrow",
                        "fetchval"})  # fmt: skip
_SQL_WORDS = re.compile(r"\b(select|insert|update|delete|create|drop|alter|where|from|pragma|"
                        r"values|join|order\s+by)\b", re.IGNORECASE)  # fmt: skip
_PATH_CALLS = frozenset({"open", "read_text", "read_bytes", "write_text", "write_bytes", "remove",
                         "unlink", "rmdir", "rmtree", "listdir", "scandir", "makedirs", "mkdir",
                         "rename", "replace", "copy", "copyfile", "copytree", "move", "iterdir",
                         "send_file", "FileResponse"})  # fmt: skip
_URL_CALLS = frozenset({"get", "post", "put", "patch", "delete", "head", "request", "urlopen",
                        "Request", "stream", "fetch"})  # fmt: skip
_CONTAINMENT = re.compile(r"is_relative_to|relative_to|commonpath|commonprefix|realpath|"
                          r"(valid|safe|allowed|within|contain|sanitiz|guard|inside|ensure_in)",
                          re.IGNORECASE)  # fmt: skip
# `if "/" in run_id or ".." in run_id: raise`: rejecting separators is containment too
_SEPARATOR_GUARD = re.compile(r"""['"](/|\\\\|\.\.)['"]\s+in\b|startswith\(\s*['"]\.""")
_CONTEXT_PARAMS = frozenset({"self", "cls", "ctx", "context"})


def _name(node: ast.AST) -> str:
    if isinstance(node, ast.Name):
        return node.id
    if isinstance(node, ast.Attribute):
        base = _name(node.value)
        return f"{base}.{node.attr}" if base else node.attr
    if isinstance(node, ast.Call):
        return _name(node.func)
    return ""


def _short(node: ast.AST) -> str:
    return _name(node).rsplit(".", 1)[-1]


@dataclass
class _Flow:
    """Taint state inside one function: which names hold tool input, and in what shape."""

    tool: str
    source: dict[str, str]  # tainted name -> the tool argument it came from
    shapes: dict[str, Shape] = field(default_factory=dict[str, Shape])

    def taint_of(self, node: ast.AST) -> tuple[Shape, str] | None:
        """(shape, argument) if `node` carries tool input."""
        if isinstance(node, ast.Name) and node.id in self.source:
            return self.shapes.get(node.id, "whole"), self.source[node.id]
        if isinstance(node, (ast.Attribute, ast.Subscript)):
            inner = self.taint_of(node.value)
            if inner and isinstance(node, ast.Subscript) and isinstance(node.slice, ast.Constant):
                return inner[0], str(node.slice.value)  # arguments["branch"]
            return inner
        if isinstance(node, ast.Call):
            if _name(node.func) in _SANITIZERS or _short(node.func) in _SANITIZERS:
                return None
            if isinstance(node.func, ast.Attribute):
                if node.func.attr == "format" and isinstance(node.func.value, ast.Constant):
                    found = [t for a in [*node.args, *(k.value for k in node.keywords)]
                             if (t := self.taint_of(a))]  # fmt: skip
                    return ("mixed", found[0][1]) if found else None
                if node.func.attr == "join" and node.args:
                    if _name(node.func.value) in ("os.path", "path", "posixpath"):
                        return self._joined(node.args)
                    return self._mixed_parts(node.args[0])
                # str methods keep the shape: x.strip(), x.lower()
                inner = self.taint_of(node.func.value)
                if inner:
                    return inner
            if _short(node.func) in ("Path", "PurePath", "PosixPath") and node.args:
                return self._joined(node.args)
            if _short(node.func) in ("str", "repr", "format"):
                found = [t for a in node.args if (t := self.taint_of(a))]
                return found[0] if found else None
            return None
        if isinstance(node, ast.JoinedStr):
            return self._mixed_parts(node)
        if isinstance(node, ast.BinOp):
            left, right = self.taint_of(node.left), self.taint_of(node.right)
            if isinstance(node.op, ast.Div) and right and not left:
                return "based", right[1]  # Path(ROOT) / name
            if isinstance(node.op, (ast.Add, ast.Mod)) and (left or right):
                has_text = any(isinstance(n, ast.Constant) and isinstance(n.value, str)
                               for n in ast.walk(node))  # fmt: skip
                found = left or right
                assert found is not None
                return ("mixed" if has_text else found[0]), found[1]
            return left or right
        if isinstance(node, (ast.List, ast.Tuple)):
            found = [t for e in node.elts if (t := self.taint_of(e))]
            return found[0] if found else None
        return None

    def _joined(self, parts: list[ast.expr]) -> tuple[Shape, str] | None:
        found = [(i, t) for i, p in enumerate(parts) if (t := self.taint_of(p))]
        if not found:
            return None
        i, (shape, arg) = found[0]
        return ("based" if i > 0 and shape == "whole" else shape), arg

    def _mixed_parts(self, node: ast.AST) -> tuple[Shape, str] | None:
        """f-strings and " ".join([...]): each interpolated expression is judged whole, so
        f"git log {shlex.quote(branch)}" is clean."""
        if isinstance(node, ast.JoinedStr):
            parts = [v.value if isinstance(v, ast.FormattedValue) else v for v in node.values]
        elif isinstance(node, (ast.List, ast.Tuple)):
            parts = list(node.elts)
        else:
            return self.taint_of(node)
        found = [t for part in parts if (t := self.taint_of(part))]
        if not found:
            return None
        has_text = any(isinstance(n, ast.Constant) and isinstance(n.value, str) and n.value.strip()
                       for n in parts)  # fmt: skip
        return ("mixed" if has_text else found[0][0]), found[0][1]

    def assign(self, target: ast.AST, value: ast.AST) -> bool:
        """Propagate into `target`; True if anything changed."""
        taint = self.taint_of(value)
        if taint is None or not isinstance(target, ast.Name):
            return False
        shape, arg = taint
        old = self.shapes.get(target.id) if target.id in self.source else None
        if old is not None and _RANK[old] >= _RANK[shape]:
            return False
        self.source[target.id], self.shapes[target.id] = arg, shape
        return True


def _literal_text(node: ast.AST) -> str:
    return " ".join(n.value for n in ast.walk(node)
                    if isinstance(n, ast.Constant) and isinstance(n.value, str))  # fmt: skip


def _host_is_tainted(node: ast.AST, flow: _Flow) -> bool:
    """f"http://{host}/x", "https://" + host: the input decides which server is contacted."""
    if isinstance(node, ast.Name) and node.id in flow.source:
        return False  # a whole URL: a fetch tool by design
    if isinstance(node, ast.JoinedStr):
        prefix = ""
        for part in node.values:
            if isinstance(part, ast.Constant) and isinstance(part.value, str):
                prefix += part.value
            elif flow.taint_of(part.value if isinstance(part, ast.FormattedValue) else part):
                return re.search(r"://[^/]*$", prefix) is not None
            else:
                prefix += "x"
        return False
    if isinstance(node, ast.BinOp) and isinstance(node.op, ast.Add):
        prefix = ""
        for part in _concat_parts(node):  # "https://" + host + "/x"
            if flow.taint_of(part):
                return re.search(r"://[^/]*$", prefix) is not None
            prefix += _literal_text(part) if isinstance(part, ast.Constant) else "x"
    return False


def _concat_parts(node: ast.AST) -> list[ast.AST]:
    if isinstance(node, ast.BinOp) and isinstance(node.op, ast.Add):
        return [*_concat_parts(node.left), *_concat_parts(node.right)]
    return [node]


class _Analyzer:
    def __init__(self, path: str, tree: ast.Module, lines: list[str]) -> None:
        self.path, self.tree, self.lines = path, tree, lines
        self.hits: list[SourceHit] = []
        self.functions: dict[str, ast.FunctionDef | ast.AsyncFunctionDef] = {}
        for node in ast.walk(tree):
            if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
                self.functions.setdefault(node.name, node)
        # modules imported here (`from . import tools`): tools.run(x) may be in another file
        imports = [n for n in ast.walk(tree) if isinstance(n, (ast.Import, ast.ImportFrom))]
        self.modules = {(a.asname or a.name).split(".")[0] for n in imports for a in n.names}
        # every function in the package, set by analyze_package
        self.package: dict[str, tuple[_Analyzer, ast.FunctionDef | ast.AsyncFunctionDef]] = {}

    def hit(self, node: ast.AST, kind: SourceHitKind, detail: str) -> None:
        line = getattr(node, "lineno", 1)
        if any(h.line == line and h.kind == kind for h in self.hits):
            return  # reached again through another handler
        code = self.lines[line - 1].strip() if 0 < line <= len(self.lines) else ""
        self.hits.append(SourceHit(kind=kind, file=self.path, line=line, code=code[:200],
                                   detail=detail))  # fmt: skip

    def handlers(self) -> list[tuple[str, ast.FunctionDef | ast.AsyncFunctionDef, list[str]]]:
        """(tool name, function, tainted parameter names)."""
        out: list[tuple[str, ast.FunctionDef | ast.AsyncFunctionDef, list[str]]] = []
        registered = {a.id for n in ast.walk(self.tree) if isinstance(n, ast.Call)
                      and _short(n.func) == "add_tool"
                      for a in n.args[:1] if isinstance(a, ast.Name)}  # fmt: skip
        for fn in self.functions.values():
            names = {_short(d) for d in fn.decorator_list}
            params = [a.arg for a in [*fn.args.posonlyargs, *fn.args.args, *fn.args.kwonlyargs]
                      if a.arg not in _CONTEXT_PARAMS]  # fmt: skip
            if "call_tool" in names:  # low-level server: (name, arguments)
                out.append(("call_tool", fn, params[1:] or params))
            elif "tool" in names or fn.name in registered:
                out.append((fn.name, fn, params))
        return out

    def run(self) -> list[SourceHit]:
        for tool, fn, params in self.handlers():
            self.analyze(tool, fn, _Flow(tool, {p: p for p in params}), depth=0)
        return self.hits

    def analyze(self, tool: str, fn: ast.AST, flow: _Flow, depth: int,
                checked: bool = False) -> None:  # fmt: skip
        """`checked`: a caller already checked containment (the sink may sit in a helper)."""
        body = [n for n in ast.walk(fn)]
        for _ in range(4):  # flow-insensitive: assignments until nothing changes
            changed = False
            for node in body:
                if isinstance(node, ast.Assign):
                    changed |= any(flow.assign(t, node.value) for t in node.targets)
                elif isinstance(node, (ast.AnnAssign, ast.AugAssign, ast.NamedExpr)):
                    if node.value is not None:
                        changed |= flow.assign(node.target, node.value)
                elif isinstance(node, (ast.For, ast.comprehension)):
                    changed |= flow.assign(node.target, node.iter)
                elif isinstance(node, ast.withitem) and node.optional_vars is not None:
                    changed |= flow.assign(node.optional_vars, node.context_expr)
            if not changed:
                break
        contained = checked or bool(
            _CONTAINMENT.search(ast.dump(fn)) or _SEPARATOR_GUARD.search(ast.unparse(fn))
        )
        for node in body:
            if isinstance(node, ast.Call):
                self.sink(node, flow, contained)
                if depth < MAX_DEPTH:
                    self.follow(node, flow, depth, contained)

    def follow(self, call: ast.Call, flow: _Flow, depth: int, checked: bool = False) -> None:
        # helper(x) or self.helper(x); not subprocess.run(...) that shares a local name
        func = call.func
        base = _name(func.value) if isinstance(func, ast.Attribute) else ""
        local = isinstance(func, ast.Name) or base in ("self", "cls")
        owner: _Analyzer = self
        callee = self.functions.get(_short(func)) if local else None
        if callee is None and (local or base in self.modules) and _short(func) in self.package:
            owner, callee = self.package[_short(func)]  # defined in another file
        if callee is None:
            return
        params = [a.arg for a in [*callee.args.posonlyargs, *callee.args.args]
                  if a.arg not in _CONTEXT_PARAMS]  # fmt: skip
        inner = _Flow(flow.tool, {})
        for param, arg in zip(params, call.args, strict=False):
            if taint := flow.taint_of(arg):
                inner.source[param], inner.shapes[param] = taint[1], taint[0]
        for kw in call.keywords:
            if kw.arg in params and (taint := flow.taint_of(kw.value)):
                inner.source[kw.arg], inner.shapes[kw.arg] = taint[1], taint[0]
        if inner.source:
            owner.analyze(flow.tool, callee, inner, depth + 1, checked)

    def sink(self, call: ast.Call, flow: _Flow, contained: bool) -> None:
        func, short = _name(call.func), _short(call.func)
        tool = flow.tool
        first = call.args[0] if call.args else next(
            (k.value for k in call.keywords if k.arg in ("args", "cmd", "url", "sql", "query")),
            None)  # fmt: skip
        if not contained and short in _PATH_CALLS:
            receiver = call.func.value if isinstance(call.func, ast.Attribute) else None
            for candidate in (first, receiver):  # open(ROOT / name), (ROOT / name).read_text()
                based = flow.taint_of(candidate) if candidate is not None else None
                if based and based[0] == "based":
                    self.hit(call, "path_traversal", f"tool {tool}: argument {based[1]} is joined "
                             f"to a base directory and used by {func}() without a containment "
                             "check")  # fmt: skip
                    break
        if first is None:
            return
        taint = flow.taint_of(first)
        shell = any(k.arg == "shell" and isinstance(k.value, ast.Constant) and k.value.value
                    for k in call.keywords)  # fmt: skip
        if (
            taint
            and taint[0] == "mixed"
            and (
                func in _ALWAYS_SHELL or short in _ALWAYS_SHELL or (short in _SHELL_CALLS and shell)
            )
        ):
            self.hit(call, "shell_injection", f"tool {tool}: argument {taint[1]} is put into a "
                     f"shell command run by {func}()")  # fmt: skip
        elif short in _SHELL_CALLS and isinstance(first, (ast.List, ast.Tuple)) and first.elts:
            head = _literal_text(first.elts[0]) if len(first.elts) > 2 else ""
            if (
                head.split("/")[-1] in ("sh", "bash", "zsh")
                and _literal_text(first.elts[1]) == "-c"
            ):
                inner = flow.taint_of(first.elts[2])
                if inner and inner[0] == "mixed":
                    self.hit(call, "shell_injection", f"tool {tool}: argument {inner[1]} is put "
                             f"into a `sh -c` command run by {func}()")  # fmt: skip
        if (
            taint
            and taint[0] == "mixed"
            and short in _SQL_CALLS
            and _SQL_WORDS.search(_literal_text(first))
        ):
            self.hit(call, "sql_injection", f"tool {tool}: argument {taint[1]} is put into a SQL "
                     f"string run by {func}()")  # fmt: skip
        if short in _URL_CALLS and _host_is_tainted(first, flow):
            arg = (flow.taint_of(first) or ("", "?"))[1]
            self.hit(call, "ssrf", f"tool {tool}: argument {arg} sets the host of a URL "
                     f"requested by {func}()")  # fmt: skip


def analyze_package(files: list[tuple[str, str]]) -> list[SourceHit]:
    """Hits across a package's files: handlers in one file, sinks in another."""
    analyzers: list[_Analyzer] = []
    for path, text in files:
        try:
            tree = ast.parse(text, filename=path)
        except (SyntaxError, ValueError):
            continue
        analyzers.append(_Analyzer(path, tree, text.splitlines()))
    package: dict[str, tuple[_Analyzer, ast.FunctionDef | ast.AsyncFunctionDef]] = {}
    for analyzer in analyzers:
        for name, fn in analyzer.functions.items():
            package.setdefault(name, (analyzer, fn))
    for analyzer in analyzers:
        analyzer.package = package
    for analyzer in analyzers:
        analyzer.run()
    return [h for a in analyzers for h in a.hits]


def analyze(path: str, text: str) -> list[SourceHit]:
    return analyze_package([(path, text)])

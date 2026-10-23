"""Taint analysis for JavaScript / TypeScript MCP servers (see taint_python.py for the model).

Handlers: `server.tool(name, ..., handler)`, `server.registerTool(name, config, handler)`,
FastMCP-TS `addTool({ name, execute })`, and the low-level
`setRequestHandler(CallToolRequestSchema, (request) => ...)` (where `request` is the input).
The first parameter is tainted: destructured names (`({ path, url })`) or the whole object
(`args.path`, `request.params.arguments.path`). Taint follows declarations, assignments and
calls into functions and methods of the same file (two levels).
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from typing import Literal

from mcpiranha.core.models import SourceHit, SourceHitKind
from mcpiranha.source.javascript import Node, callee_of, node_text, parser, string_value, walk

Shape = Literal["whole", "mixed", "based"]
_RANK = {"whole": 1, "based": 2, "mixed": 3}
MAX_DEPTH = 2
_FUNCTIONS = ("arrow_function", "function_expression", "function_declaration", "function",
              "method_definition", "generator_function_declaration")  # fmt: skip

_SANITIZERS = re.compile(r"(^|\.)(quote|shellQuote|shellescape|escapeShellArg|escape|"
                         r"escapeId|escapeLiteral|escapeIdentifier|format|Number|parseInt|"
                         r"parseFloat|Boolean|encodeURIComponent|encodeURI|basename)$")  # fmt: skip
_HANDLER_KEYS = ("execute", "handler", "callback", "cb", "run", "fn")
_EXEC_ALIAS = re.compile(
    r"\b(?:const|let|var)\s+([\w$]+)\s*=\s*(?:\(0,\s*)?[\w$.]*promisify\)?\s*\(\s*"
    r"(?:\(0,\s*)?(?:[\w$.]*\.)?(exec|execFile)\b"
    r"|\b(?:const|let|var)\s+([\w$]+)\s*=\s*(?:[\w$.]*\.)?(exec|execSync)\s*[;,\n]"
)
_TS_IMPORT = re.compile(r"^[\w$]+_\d+\.[\w$]+$")  # tools_1.run, from `(0, tools_1.run)(...)`
_SHELL = frozenset({"exec", "execSync"})
_SPAWN = frozenset({"spawn", "spawnSync", "execFile", "execFileSync", "execa", "execaSync"})
_ALWAYS_SHELL = frozenset({"execaCommand", "execaCommandSync"})
_SQL = frozenset({"query", "execute", "raw", "$queryRawUnsafe", "$executeRawUnsafe", "prepare",
                  "unsafe", "exec", "all", "run", "get", "each"})  # fmt: skip
_SQL_WORDS = re.compile(r"\b(select|insert|update|delete|create|drop|alter|where|from|pragma|"
                        r"values|join|order\s+by)\b", re.IGNORECASE)  # fmt: skip
_PATH = frozenset({"readFile", "readFileSync", "writeFile", "writeFileSync", "appendFile",
                   "appendFileSync", "unlink", "unlinkSync", "rm", "rmSync", "rmdir", "rmdirSync",
                   "readdir", "readdirSync", "createReadStream", "createWriteStream", "copyFile",
                   "copyFileSync", "rename", "renameSync", "mkdir", "mkdirSync", "sendFile",
                   "open", "openSync", "readJson", "readJsonSync", "outputFile",
                   "outputFileSync"})  # fmt: skip
_URL = frozenset({"fetch", "get", "post", "put", "patch", "delete", "head", "request", "got",
                  "axios", "ky"})  # fmt: skip
_CONTAINMENT = re.compile(r"startsWith|path\.relative|\brelative\(|realpath|isPathAllowed|"
                          r"""includes\(\s*['"](\.\.|/)['"]\s*\)|"""
                          r"(valid|safe|allowed|within|contain|sanitiz|guard|inside)\w*\(",
                          re.IGNORECASE)  # fmt: skip


def _short(callee: str) -> str:
    return callee.rsplit(".", 1)[-1]


def _params(fn: Node) -> list[Node]:
    params = fn.child_by_field_name("parameters")
    if params is None:
        single = fn.child_by_field_name("parameter")
        return [single] if single is not None else []
    return [c for c in params.named_children if c.type != "comment"]


def _pattern_names(node: Node) -> list[tuple[str, str]]:
    """(local name, argument name) bound by a parameter or destructuring pattern."""
    if node.type in ("required_parameter", "optional_parameter"):
        inner = node.child_by_field_name("pattern")
        return _pattern_names(inner) if inner is not None else []
    if node.type == "assignment_pattern":
        left = node.child_by_field_name("left")
        return _pattern_names(left) if left is not None else []
    if node.type == "identifier":
        return [(node_text(node), "")]  # the whole input object
    if node.type == "object_pattern":
        out: list[tuple[str, str]] = []
        for child in node.named_children:
            if child.type == "shorthand_property_identifier_pattern":
                out.append((node_text(child), node_text(child)))
            elif child.type == "pair_pattern":
                key, value = child.child_by_field_name("key"), child.child_by_field_name("value")
                for local, _ in _pattern_names(value) if value is not None else []:
                    out.append((local, node_text(key)))
            elif child.type == "object_assignment_pattern":
                left = child.child_by_field_name("left")
                if left is not None:
                    out.append((node_text(left), node_text(left)))
        return out
    return []


@dataclass
class _Flow:
    tool: str
    source: dict[str, str]  # name -> argument ("" = the whole input object)
    shapes: dict[str, Shape] = field(default_factory=dict[str, Shape])

    def taint_of(self, node: Node | None) -> tuple[Shape, str] | None:
        if node is None:
            return None
        kind = node.type
        if kind in ("parenthesized_expression", "await_expression", "as_expression",
                    "non_null_expression", "satisfies_expression"):  # fmt: skip
            inner = node.named_children[0] if node.named_children else None
            return self.taint_of(inner)
        if kind == "identifier":
            name = node_text(node)
            if name in self.source:
                return self.shapes.get(name, "whole"), self.source[name] or name
            return None
        if kind in ("member_expression", "subscript_expression"):
            obj = self.taint_of(node.child_by_field_name("object"))
            if obj is None:
                return None
            prop = node.child_by_field_name("property") or node.child_by_field_name("index")
            key = (string_value(prop) or "") if prop is not None and prop.type == "string" else (
                node_text(prop))  # fmt: skip
            # args.path -> "path"; request.params.arguments.path -> "path"
            plain = key not in ("params", "arguments", "input") and not key.isdigit()
            return obj[0], key if plain else obj[1]
        if kind == "call_expression":
            callee = callee_of(node)
            args = node.child_by_field_name("arguments")
            arg_nodes = args.named_children if args is not None else []
            if _SANITIZERS.search(callee):
                return None
            if callee in ("path.join", "path.resolve", "join", "resolve", "path.posix.join"):
                found = [(i, t) for i, a in enumerate(arg_nodes) if (t := self.taint_of(a))]
                if not found:
                    return None
                i, (shape, arg) = found[0]
                return ("based" if i > 0 and shape == "whole" else shape), arg
            if callee in ("String", "decodeURIComponent"):
                return self.taint_of(arg_nodes[0]) if arg_nodes else None
            func = node.child_by_field_name("function")
            if func is not None and func.type == "member_expression":
                # x.trim(), x.toLowerCase(), parts.join(" ")
                return self.taint_of(func.child_by_field_name("object"))
            return None
        if kind == "template_string":
            subs = [c for c in node.named_children if c.type == "template_substitution"]
            inside = [s.named_children[0] for s in subs if s.named_children]
            found = [t for e in inside if (t := self.taint_of(e))]
            if not found:
                return None
            text = any(
                c.type == "string_fragment" and node_text(c).strip() for c in node.named_children
            )
            return ("mixed" if text else found[0][0]), found[0][1]
        if kind == "binary_expression" and node_text(node.child_by_field_name("operator")) == "+":
            left = self.taint_of(node.child_by_field_name("left"))
            right = self.taint_of(node.child_by_field_name("right"))
            found = left or right
            if found is None:
                return None
            has_text = any(c.type in ("string", "template_string") for c in walk(node))
            return ("mixed" if has_text else found[0]), found[1]
        if kind == "array":
            found = [t for c in node.named_children if (t := self.taint_of(c))]
            return found[0] if found else None
        return None

    def bind(self, pattern: Node | None, value: Node | None, *, appended: bool = False) -> bool:
        taint = self.taint_of(value)
        if pattern is None or taint is None:
            return False
        if appended:  # appended to an existing string: text around it
            taint = ("mixed", taint[1])
        changed = False
        if pattern.type == "object_pattern":  # const { path } = args
            for local, arg in _pattern_names(pattern):
                if local not in self.source:
                    self.source[local], self.shapes[local] = arg or local, "whole"
                    changed = True
            return changed
        if pattern.type != "identifier":
            return False
        name = node_text(pattern)
        old = self.shapes.get(name) if name in self.source else None
        if old is not None and _RANK[old] >= _RANK[taint[0]]:
            return False
        self.source[name], self.shapes[name] = taint[1], taint[0]
        return True


def _concat_parts(node: Node) -> list[Node]:
    if node.type == "binary_expression" and node_text(node.child_by_field_name("operator")) == "+":
        left, right = node.child_by_field_name("left"), node.child_by_field_name("right")
        return [*(_concat_parts(left) if left else []), *(_concat_parts(right) if right else [])]
    return [node]


def _host_is_tainted(node: Node | None, flow: _Flow) -> bool:
    """`http://${host}/x`, "https://" + host: the input decides which server is contacted."""
    if node is None:
        return False
    if node.type == "template_string":
        prefix = ""
        for child in node.named_children:
            if child.type == "string_fragment":
                prefix += node_text(child)
            elif child.type == "template_substitution":
                inner = child.named_children[0] if child.named_children else None
                if flow.taint_of(inner):
                    return re.search(r"://[^/]*$", prefix) is not None
                prefix += "x"
        return False
    if node.type == "binary_expression":
        prefix = ""
        for part in _concat_parts(node):  # "https://" + host + "/x"
            if flow.taint_of(part):
                return re.search(r"://[^/]*$", prefix) is not None
            prefix += string_value(part) or "x"
    return False


class _Analyzer:
    def __init__(self, path: str, source: bytes, root: Node) -> None:
        self.path, self.root = path, root
        self.lines = source.decode("utf-8", "replace").splitlines()
        self.hits: list[SourceHit] = []
        self.functions: dict[str, Node] = {}
        self.package: dict[str, tuple[_Analyzer, Node]] = {}  # set by analyze_package
        text = source.decode("utf-8", "replace")
        # const execAsync = promisify(exec); const run = child_process.execSync
        self.shell_aliases = {(m.group(1) or m.group(3)): (m.group(2) or m.group(4))
                              for m in _EXEC_ALIAS.finditer(text)}  # fmt: skip
        for node in walk(root):
            if node.type in ("function_declaration", "method_definition"):
                self.functions.setdefault(node_text(node.child_by_field_name("name")), node)
            elif node.type == "variable_declarator":
                value = node.child_by_field_name("value")
                if value is not None and value.type in _FUNCTIONS:
                    self.functions.setdefault(node_text(node.child_by_field_name("name")), value)

    def hit(self, node: Node, kind: SourceHitKind, detail: str) -> None:
        row, column = node.start_point
        if any(h.line == row + 1 and h.kind == kind for h in self.hits):
            return  # reached again through another handler
        line = self.lines[row] if row < len(self.lines) else ""
        if len(line) > 200:
            line = line[max(0, column - 80) : column + 120]
        self.hits.append(SourceHit(kind=kind, file=self.path, line=row + 1, code=line.strip(),
                                   detail=detail))  # fmt: skip

    def _function(self, node: Node | None) -> Node | None:
        """A function literal, or the function a name refers to (`registerTool(n, c, execute)`)."""
        if node is None:
            return None
        if node.type in _FUNCTIONS:
            return node
        if node.type == "identifier":
            return self.functions.get(node_text(node))
        return None

    def handlers(self) -> list[tuple[str, Node]]:
        out: list[tuple[str, Node]] = []
        for node in walk(self.root):
            if node.type != "call_expression":
                continue
            callee = _short(callee_of(node))
            args = node.child_by_field_name("arguments")
            items = args.named_children if args is not None else []
            if callee in ("tool", "registerTool", "addTool") and items:
                if items[0].type == "object":  # registerTool({ name, handler }), addTool(...)
                    pairs = {node_text(p.child_by_field_name("key")): p.child_by_field_name("value")
                             for p in items[0].named_children if p.type == "pair"}  # fmt: skip
                    found = [self._function(pairs.get(key)) for key in _HANDLER_KEYS]
                    fn = next((f for f in found if f is not None), None)
                    name = string_value(pairs.get("name")) or node_text(pairs.get("name"))
                else:  # tool(name, [description], [schema], handler)
                    fn = self._function(items[-1]) if len(items) > 1 else None
                    name = string_value(items[0]) or node_text(items[0])
                if fn is not None:
                    out.append((name or "tool", fn))
            elif (
                callee == "setRequestHandler"
                and len(items) == 2
                and "CallTool" in node_text(items[0])
            ):
                fn = self._function(items[1])
                if fn is not None:
                    out.append(("call_tool", fn))
        return out

    def run(self) -> list[SourceHit]:
        for tool, fn in self.handlers():
            params = _params(fn)
            if not params:
                continue
            source = dict(_pattern_names(params[0]))
            if source:
                self.analyze(fn, _Flow(tool, {k: v for k, v in source.items()}), depth=0)
        return self.hits

    def analyze(self, fn: Node, flow: _Flow, depth: int, checked: bool = False) -> None:
        """`checked`: a caller already checked containment (the sink may sit in a helper)."""
        body = list(walk(fn))
        for _ in range(4):
            changed = False
            for node in body:
                if node.type == "variable_declarator":
                    changed |= flow.bind(node.child_by_field_name("name"),
                                         node.child_by_field_name("value"))  # fmt: skip
                elif node.type == "assignment_expression":
                    changed |= flow.bind(node.child_by_field_name("left"),
                                         node.child_by_field_name("right"))  # fmt: skip
                elif node.type == "augmented_assignment_expression":  # command += " " + x
                    left, right = (
                        node.child_by_field_name("left"),
                        node.child_by_field_name("right"),
                    )
                    changed |= flow.bind(left, right, appended=True)
            if not changed:
                break
        contained = checked or bool(_CONTAINMENT.search(node_text(fn)))
        for node in body:
            if node.type in ("call_expression", "new_expression"):
                self.sink(node, flow, contained)
                if depth < MAX_DEPTH:
                    self.follow(node, flow, depth, contained)

    def follow(self, call: Node, flow: _Flow, depth: int, checked: bool = False) -> None:
        # helper(x) or this.helper(x); not child_process.exec(...) sharing a local name
        name = callee_of(call)
        # plain names, this.x, and TypeScript's compiled imports (`(0, tools_1.run)(...)`)
        local = "." not in name or name.startswith("this.") or bool(_TS_IMPORT.match(name))
        owner: _Analyzer = self
        callee = self.functions.get(_short(name)) if local else None
        if callee is None and local and _short(name) in self.package:
            owner, callee = self.package[_short(name)]  # defined in another file
        args = call.child_by_field_name("arguments")
        if callee is None or args is None:
            return
        inner = _Flow(flow.tool, {})
        for param, arg in zip(_params(callee), args.named_children, strict=False):
            taint = flow.taint_of(arg)
            if taint is None:
                continue
            names = _pattern_names(param)
            if len(names) == 1 and names[0][1] == "":
                inner.source[names[0][0]], inner.shapes[names[0][0]] = taint[1], taint[0]
            else:  # a destructured object parameter: every field carries the input
                for local, key in names:
                    inner.source[local], inner.shapes[local] = key or taint[1], "whole"
        if inner.source:
            owner.analyze(callee, inner, depth + 1, checked)

    def sink(self, call: Node, flow: _Flow, contained: bool) -> None:
        callee = callee_of(call)
        short = self.shell_aliases.get(_short(callee), _short(callee))
        args = call.child_by_field_name("arguments")
        items = args.named_children if args is not None else []
        first = items[0] if items else None
        taint = flow.taint_of(first)
        tool = flow.tool
        options = " ".join(node_text(a) for a in items[1:])
        sql_text = " ".join(node_text(c) for c in walk(first) if c.type == "string_fragment") if (
            first is not None) else ""  # fmt: skip
        is_sql = bool(_SQL_WORDS.search(sql_text))
        if taint and taint[0] == "mixed":
            if short in _SQL and is_sql:
                self.hit(call, "sql_injection", f"tool {tool}: argument {taint[1]} is put into a "
                         f"SQL string run by {callee}()")  # fmt: skip
            elif (
                short in _SHELL
                or short in _ALWAYS_SHELL
                or (short in _SPAWN and re.search(r"\bshell\s*:\s*true", options))
            ):
                self.hit(call, "shell_injection", f"tool {tool}: argument {taint[1]} is put into "
                         f"a shell command run by {callee}()")  # fmt: skip
        if (
            short in _SPAWN
            and first is not None
            and string_value(first) in ("sh", "bash", "/bin/sh", "/bin/bash", "zsh")
            and len(items) > 1
            and items[1].type == "array"
        ):
            elements = items[1].named_children
            if len(elements) > 1 and string_value(elements[0]) == "-c":
                inner = flow.taint_of(elements[1])
                if inner and inner[0] == "mixed":
                    self.hit(call, "shell_injection", f"tool {tool}: argument {inner[1]} is put "
                             f"into a `sh -c` command run by {callee}()")  # fmt: skip
        if short in _URL and _host_is_tainted(first, flow):
            arg = (taint or ("", "?"))[1]
            self.hit(call, "ssrf", f"tool {tool}: argument {arg} sets the host of a URL requested "
                     f"by {callee}()")  # fmt: skip
        if short in _PATH and not contained and taint and taint[0] == "based":
            detail = (f"tool {tool}: argument {taint[1]} is joined to a base directory and used "
                      f"by {callee}() without a containment check")  # fmt: skip
            self.hit(call, "path_traversal", detail)


def analyze_package(files: list[tuple[str, bytes]]) -> list[SourceHit]:
    """Hits across a package's files: handlers in one file, sinks in another."""
    analyzers: list[_Analyzer] = []
    for path, source in files:
        typescript = path.endswith((".ts", ".mts", ".cts"))
        kind = "tsx" if path.endswith(".tsx") else "ts" if typescript else "js"
        analyzers.append(_Analyzer(path, source, parser(kind).parse(source).root_node))
    package: dict[str, tuple[_Analyzer, Node]] = {}
    for analyzer in analyzers:
        for name, fn in analyzer.functions.items():
            package.setdefault(name, (analyzer, fn))
    for analyzer in analyzers:
        analyzer.package = package
    for analyzer in analyzers:
        analyzer.run()
    return [h for a in analyzers for h in a.hits]


def analyze(path: str, source: bytes) -> list[SourceHit]:
    return analyze_package([(path, source)])

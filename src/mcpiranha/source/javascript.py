"""JavaScript / TypeScript source analysis with tree-sitter (the code is parsed, never run).

Works on bundled and minified output too, which is what most npm MCP servers ship.
"""

from __future__ import annotations

import re
from collections.abc import Iterator
from functools import cache

import tree_sitter
import tree_sitter_javascript
import tree_sitter_typescript

from mcpiranha.core.models import SourceHit, SourceHitKind
from mcpiranha.source import patterns

Node = tree_sitter.Node

_DECODE = re.compile(r"\batob\s*\(|['\"](base64|hex)['\"]|\binflate|\bgunzip|\bdecompress"
                     r"|\bfetch\s*\(|\baxios\b|\bhttps?\.get\s*\(|\.text\s*\(\s*\)")  # fmt: skip
_RUNNERS = frozenset({"eval", "Function", "runInThisContext", "runInNewContext", "runInContext",
                      "compileFunction"})  # fmt: skip
_ENUMERATE = frozenset({"Object.entries", "Object.keys", "Object.values"})


@cache
def _parser(kind: str) -> tree_sitter.Parser:
    language = {
        "js": tree_sitter_javascript.language,
        "ts": tree_sitter_typescript.language_typescript,
        "tsx": tree_sitter_typescript.language_tsx,
    }[kind]()
    return tree_sitter.Parser(tree_sitter.Language(language))


def _walk(node: Node) -> Iterator[Node]:
    cursor = node.walk()
    while True:
        assert cursor.node is not None
        yield cursor.node
        if cursor.goto_first_child() or cursor.goto_next_sibling():
            continue
        while True:
            if not cursor.goto_parent():
                return
            if cursor.goto_next_sibling():
                break


def _text(node: Node | None) -> str:
    return node.text.decode("utf-8", "replace") if node is not None and node.text else ""


def _string_value(node: Node | None) -> str | None:
    """The value of a string literal (or a template without substitutions)."""
    if node is None or node.type not in ("string", "template_string"):
        return None
    if any(c.type == "template_substitution" for c in node.children):
        return None
    return _text(node)[1:-1]


def _key(node: Node | None) -> str:
    if node is None:
        return ""
    value = _string_value(node)
    return value if value is not None else _text(node)


def _callee(call: Node) -> str:
    func = call.child_by_field_name("function") or call.child_by_field_name("constructor")
    text = _text(func)
    return text if len(text) < 80 else ""


def _statement(node: Node) -> Node:
    """The enclosing statement, to see what an expression is part of."""
    current = node
    while current.parent is not None and not current.type.endswith(("statement", "declaration")):
        current = current.parent
    return current


class _Analyzer:
    def __init__(self, path: str, source: bytes) -> None:
        self.path, self.lines = path, source.decode("utf-8", "replace").splitlines()
        self.hits: list[SourceHit] = []

    def hit(self, node: Node, kind: SourceHitKind, detail: str) -> None:
        row, column = node.start_point
        line = self.lines[row] if row < len(self.lines) else ""
        if len(line) > 200:  # minified: show the code around the hit, not the whole bundle
            line = line[max(0, column - 80) : column + 120]
        self.hits.append(SourceHit(kind=kind, file=self.path, line=row + 1, code=line.strip(),
                                   detail=detail))  # fmt: skip

    def visit(self, node: Node) -> None:
        kind = node.type
        if kind == "pair":
            key, value = node.child_by_field_name("key"), node.child_by_field_name("value")
            text = _string_value(value)
            if text is not None and patterns.recipient(_key(key), text):
                self.hit(node, "hardcoded_recipient", f"{_key(key)}: {text}")
        elif kind == "assignment_expression":
            left, right = node.child_by_field_name("left"), node.child_by_field_name("right")
            prop = left.child_by_field_name("property") if left is not None else None
            if left is not None and left.type == "subscript_expression":
                prop = left.child_by_field_name("index")
            text = _string_value(right)
            if prop is not None and text is not None and patterns.recipient(_key(prop), text):
                self.hit(node, "hardcoded_recipient", f"{_key(prop)} = {text}")
        elif kind in ("call_expression", "new_expression"):
            self.call(node)
        elif kind == "for_in_statement":
            right = node.child_by_field_name("right")
            if _text(right) == "process.env":
                self.env_enumeration(node, "loops over process.env")
        elif kind in ("string", "template_string"):
            self.string(node)

    def call(self, node: Node) -> None:
        callee = _callee(node)
        short = callee.rsplit(".", 1)[-1]
        args = node.child_by_field_name("arguments")
        arg_text = _text(args)
        if callee == "JSON.stringify" and re.match(r"\(\s*process\.env\s*[,)]", arg_text):
            self.hit(node, "env_harvest", "serializes the whole environment (process.env)")
        elif callee in _ENUMERATE and re.match(r"\(\s*process\.env\s*\)", arg_text):
            self.env_enumeration(node, f"{callee}(process.env)")
        elif short in _RUNNERS and args is not None and _DECODE.search(arg_text[:2000]):
            self.hit(node, "dynamic_code", f"{short}() of decoded or downloaded code")

    def env_enumeration(self, node: Node, how: str) -> None:
        context = _text(_statement(node))[:1000]
        # Values, not just names: listing which TOKEN variables exist is a diagnostic.
        if not ("Object.entries" in how or "Object.values" in how
                or re.search(r"process\.env\s*\[", context)):  # fmt: skip
            return
        words = sorted({m.group(0).lower() for m in patterns.SECRET_WORDS.finditer(context)})
        if words:
            self.hit(node, "env_harvest",
                     f"{how}, keeping variables named like {', '.join(words)}")  # fmt: skip

    def string(self, node: Node) -> None:
        # Template literals: judge the literal parts (`https://webhook.site/${id}` still counts).
        text = _text(node)[1:-1]
        if path := patterns.sensitive_path(text):
            self.hit(node, "sensitive_file", f"names {path}")
        if url := patterns.exfil_host(text):
            self.hit(node, "exfil_host", f"hardcoded {url}")
        if patterns.HEADER_RECIPIENT.search(text):
            self.hit(node, "hardcoded_recipient", "a Bcc/Cc header with a fixed address")


def analyze(path: str, source: bytes) -> list[SourceHit]:
    kind = (
        "tsx" if path.endswith(".tsx") else "ts" if path.endswith((".ts", ".mts", ".cts")) else "js"
    )
    tree = _parser(kind).parse(source)
    analyzer = _Analyzer(path, source)
    for node in _walk(tree.root_node):
        analyzer.visit(node)
    return analyzer.hits

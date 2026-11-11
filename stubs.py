"""Deterministic detection of hollow Python function implementations."""

from __future__ import annotations

import ast
import io
import re
import tokenize
from typing import NamedTuple


_ALLOW_RE = re.compile(r"\btruthgate\s*:\s*allow\b", re.IGNORECASE)
_PLACEHOLDER_RE = re.compile(
    r"\b(?:TODO|FIXME|placeholder|stub|temporary|not[ -]?implemented)\b",
    re.IGNORECASE,
)


class StubFinding(NamedTuple):
    """One hollow function body found in source text."""

    qualified_name: str
    name: str
    kind: str
    lineno: int
    end_lineno: int
    message: str


_MESSAGES = {
    "pass": "function body contains only pass",
    "ellipsis": "function body contains only an ellipsis",
    "not_implemented": "function body only raises NotImplementedError",
    "return_none": "function body only returns None",
    "placeholder_return": "literal return is marked by an adjacent placeholder comment",
}


def _tail_name(node: ast.AST) -> str | None:
    if isinstance(node, ast.Call):
        node = node.func
    if isinstance(node, ast.Name):
        return node.id
    if isinstance(node, ast.Attribute):
        return node.attr
    return None


def _comments(source: str) -> dict[int, list[str]]:
    found: dict[int, list[str]] = {}
    try:
        tokens = tokenize.generate_tokens(io.StringIO(source).readline)
        for token in tokens:
            if token.type == tokenize.COMMENT:
                found.setdefault(token.start[0], []).append(token.string)
    except (IndentationError, SyntaxError, tokenize.TokenError):
        return {}
    return found


def _semantic_body(node: ast.FunctionDef | ast.AsyncFunctionDef) -> list[ast.stmt]:
    body = list(node.body)
    if body and isinstance(body[0], ast.Expr) and isinstance(body[0].value, ast.Constant):
        if isinstance(body[0].value.value, str):
            body.pop(0)
    return body


def _is_literal(node: ast.AST | None) -> bool:
    if node is None:
        return False
    try:
        ast.literal_eval(node)
    except (ValueError, TypeError, SyntaxError, MemoryError, RecursionError):
        return False
    return True


class _Detector(ast.NodeVisitor):
    def __init__(self, source: str, comments: dict[int, list[str]]) -> None:
        self._lines = source.splitlines()
        self._comments = comments
        self._scope: list[str] = []
        self._parents: list[ast.AST] = []
        self._protocol_classes: set[int] = set()
        self.findings: list[StubFinding] = []

    def _visit_scoped(self, node: ast.AST, name: str) -> None:
        self._parents.append(node)
        self._scope.append(name)
        self.generic_visit(node)
        self._scope.pop()
        self._parents.pop()

    def visit_ClassDef(self, node: ast.ClassDef) -> None:
        if any(_tail_name(base) == "Protocol" for base in node.bases):
            self._protocol_classes.add(id(node))
        self._visit_scoped(node, node.name)

    def visit_FunctionDef(self, node: ast.FunctionDef) -> None:
        self._visit_function(node)

    def visit_AsyncFunctionDef(self, node: ast.AsyncFunctionDef) -> None:
        self._visit_function(node)

    def _visit_function(self, node: ast.FunctionDef | ast.AsyncFunctionDef) -> None:
        parent = self._parents[-1] if self._parents else None
        excluded = (
            isinstance(parent, ast.ClassDef) and id(parent) in self._protocol_classes
        ) or any(
            _tail_name(decorator) in {"abstractmethod", "overload"}
            for decorator in node.decorator_list
        ) or self._allowed(node)

        if not excluded:
            kind = self._kind(node)
            if kind is not None:
                qualified_name = ".".join((*self._scope, node.name))
                self.findings.append(
                    StubFinding(
                        qualified_name=qualified_name,
                        name=node.name,
                        kind=kind,
                        lineno=node.lineno,
                        end_lineno=node.end_lineno or node.lineno,
                        message=_MESSAGES[kind],
                    )
                )
        self._visit_scoped(node, node.name)

    def _allowed(self, node: ast.FunctionDef | ast.AsyncFunctionDef) -> bool:
        start = min(
            [node.lineno, *(decorator.lineno for decorator in node.decorator_list)]
        )
        for line in range(max(1, start - 1), (node.end_lineno or node.lineno) + 1):
            if any(_ALLOW_RE.search(comment) for comment in self._comments.get(line, ())):
                return True
        return False

    def _kind(self, node: ast.FunctionDef | ast.AsyncFunctionDef) -> str | None:
        body = _semantic_body(node)
        if len(body) != 1:
            return None
        statement = body[0]
        if isinstance(statement, ast.Pass):
            return "pass"
        if (
            isinstance(statement, ast.Expr)
            and isinstance(statement.value, ast.Constant)
            and statement.value.value is Ellipsis
        ):
            return "ellipsis"
        if isinstance(statement, ast.Raise) and _tail_name(statement.exc) == "NotImplementedError":
            return "not_implemented"
        if isinstance(statement, ast.Return):
            if statement.value is None or (
                isinstance(statement.value, ast.Constant) and statement.value.value is None
            ):
                return "return_none"
            if _is_literal(statement.value) and self._has_adjacent_placeholder(statement):
                return "placeholder_return"
        return None

    def _has_adjacent_placeholder(self, statement: ast.Return) -> bool:
        start = statement.lineno
        end = statement.end_lineno or start
        candidate_lines = {start, end, start - 1, end + 1}
        for line in candidate_lines:
            if line < 1:
                continue
            if line not in {start, end}:
                text = self._lines[line - 1] if line <= len(self._lines) else ""
                if not text.strip().startswith("#"):
                    continue
            if any(_PLACEHOLDER_RE.search(comment) for comment in self._comments.get(line, ())):
                return True
        return False


def find_stubs(source: str, *, filename: str = "<unknown>") -> tuple[StubFinding, ...]:
    """Return hollow function implementations in *source*.

    Invalid source and ``.pyi`` interface files fail open with no findings. The
    function performs no I/O and imports no Hermes modules.
    """

    if filename.lower().endswith(".pyi"):
        return ()
    try:
        tree = ast.parse(source, filename=filename)
    except (SyntaxError, ValueError, TypeError, MemoryError, RecursionError):
        return ()
    detector = _Detector(source, _comments(source))
    detector.visit(tree)
    return tuple(detector.findings)

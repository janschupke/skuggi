"""Three sample tools the worker can call.

- retrieve: top-k FAISS lookup, with k clamped
- calculator: safe arithmetic via ast (no eval), with an exponent cap
- file_read: read a path confined to a root directory, byte-capped

Every bound here exists because the *model* supplies the arguments: an
unclamped k dumps the whole index into the prompt, an unbounded exponent hangs
the process, and an unbounded max_bytes reads an arbitrarily large file.
"""

from __future__ import annotations

import ast
import operator
from collections.abc import Callable
from pathlib import Path

from langchain_core.tools import BaseTool, tool

from skuggi.execution import MAX_CAPTURE_BYTES
from skuggi.vectorstore import Store, format_hits

_BIN_OPS: dict[type[ast.operator], Callable[[float, float], float]] = {
    ast.Add: operator.add,
    ast.Sub: operator.sub,
    ast.Mult: operator.mul,
    ast.Div: operator.truediv,
    ast.FloorDiv: operator.floordiv,
    ast.Mod: operator.mod,
    ast.Pow: operator.pow,
}
_UNARY_OPS: dict[type[ast.unaryop], Callable[[float], float]] = {
    ast.UAdd: operator.pos,
    ast.USub: operator.neg,
}

# 2**1024 is instant and ~309 digits; 9**(9**9) is not computable. The cap sits
# above anything a chat user plausibly wants and below the range that hangs.
_MAX_POW_EXPONENT = 1024
_MAX_RETRIEVE_K = 10
_NO_RESULTS = "(no results -- the index is empty; use /ingest first)"


class _UnsafeExpressionError(ValueError):
    """Raised for an AST node the arithmetic whitelist does not allow."""

    def __init__(self, detail: str) -> None:
        super().__init__(f"disallowed expression: {detail}")


def _safe_eval(node: ast.AST) -> float:
    """Evaluate an arithmetic AST, rejecting anything outside the whitelist."""
    if isinstance(node, ast.Expression):
        return _safe_eval(node.body)
    if isinstance(node, ast.Constant):
        # bool is an int subclass; exclude it so `True+1` is not arithmetic.
        if isinstance(node.value, bool) or not isinstance(node.value, (int, float)):
            msg = f"constant {type(node.value).__name__}"
            raise _UnsafeExpressionError(msg)
        return node.value
    if isinstance(node, ast.BinOp) and type(node.op) in _BIN_OPS:
        left = _safe_eval(node.left)
        right = _safe_eval(node.right)
        if isinstance(node.op, ast.Pow) and abs(right) > _MAX_POW_EXPONENT:
            msg = f"exponent {right} exceeds the cap"
            raise _UnsafeExpressionError(msg)
        return _check_numeric(_BIN_OPS[type(node.op)](left, right))
    if isinstance(node, ast.UnaryOp) and type(node.op) in _UNARY_OPS:
        return _check_numeric(_UNARY_OPS[type(node.op)](_safe_eval(node.operand)))
    raise _UnsafeExpressionError(type(node).__name__)


def _check_numeric(value: object) -> float:
    """Reject non-real results, such as the complex value of `(-8) ** 0.5`."""
    if isinstance(value, bool) or not isinstance(value, (int, float)):
        msg = f"non-real result {type(value).__name__}"
        raise _UnsafeExpressionError(msg)
    return value


def _resolve_within(candidate: str, root: Path) -> Path | None:
    """Resolve `candidate` and return it only if it stays inside `root`.

    `resolve()` follows symlinks, so resolving before comparing is what defeats
    a link inside the root that points outside it. The comparison itself must be
    `is_relative_to` and not a string prefix test: with a prefix test a sibling
    directory whose name merely extends the root's (`<root>-secrets`) passes.

    Note this is resolve-then-open, so a symlink swapped in between the two is
    not covered. Closing that needs O_NOFOLLOW; out of proportion for a
    single-user local tool, but worth knowing it was considered.
    """
    path = Path(candidate).expanduser()
    if not path.is_absolute():
        path = root / path
    resolved = path.resolve()
    return resolved if resolved.is_relative_to(root) else None


def build_tools(
    store: Store, *, root: Path | None = None, k: int = 4
) -> list[BaseTool]:
    """Build the worker's tools, confining `file_read` to `root`.

    `root` is captured once here rather than read per call, so the sandbox
    cannot drift if anything changes the working directory mid-session -- and so
    a test can point it at a temporary directory without chdir.
    """
    sandbox_root = (root or Path.cwd()).resolve()
    default_k = k

    @tool
    def retrieve(query: str, k: int = default_k) -> str:
        """Search the local knowledge base for passages related to the query."""
        hits = store.search(query, k=max(1, min(k, _MAX_RETRIEVE_K)))
        return format_hits(hits) if hits else _NO_RESULTS

    @tool
    def calculator(expression: str) -> str:
        """Evaluate a simple arithmetic expression. Supports + - * / // % **."""
        try:
            return str(_safe_eval(ast.parse(expression, mode="eval")))
        except (
            SyntaxError,
            ValueError,
            TypeError,
            ZeroDivisionError,
            OverflowError,
            RecursionError,
        ) as exc:
            return f"error: {exc}"

    @tool
    def file_read(path: str, max_bytes: int = 8192) -> str:
        """Read up to max_bytes from a file path inside the working directory."""
        target = _resolve_within(path, sandbox_root)
        if target is None:
            return "error: path escapes the working directory"
        if not target.is_file():
            return f"error: not a file: {target}"
        limit = max(1, min(max_bytes, MAX_CAPTURE_BYTES))
        with target.open("rb") as handle:
            return handle.read(limit).decode("utf-8", errors="replace")

    return [retrieve, calculator, file_read]

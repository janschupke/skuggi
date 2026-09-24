"""Three sample tools the worker can call.

- retrieve: top-k FAISS lookup
- calculator: safe arithmetic via ast (no eval)
- file_read: read a cwd-relative path, byte-capped
"""

from __future__ import annotations

import ast
import operator
from pathlib import Path

from langchain_core.tools import BaseTool, tool

from skuggi.vectorstore import Store

_BIN_OPS = {
    ast.Add: operator.add,
    ast.Sub: operator.sub,
    ast.Mult: operator.mul,
    ast.Div: operator.truediv,
    ast.FloorDiv: operator.floordiv,
    ast.Mod: operator.mod,
    ast.Pow: operator.pow,
}
_UNARY_OPS = {ast.UAdd: operator.pos, ast.USub: operator.neg}


def _safe_eval(node: ast.AST) -> float | int:
    if isinstance(node, ast.Expression):
        return _safe_eval(node.body)
    if isinstance(node, ast.Constant) and isinstance(node.value, (int, float)):
        return node.value
    if isinstance(node, ast.BinOp) and type(node.op) in _BIN_OPS:
        return _BIN_OPS[type(node.op)](_safe_eval(node.left), _safe_eval(node.right))
    if isinstance(node, ast.UnaryOp) and type(node.op) in _UNARY_OPS:
        return _UNARY_OPS[type(node.op)](_safe_eval(node.operand))
    raise ValueError(f"disallowed node: {ast.dump(node)}")


def build_tools(store: Store) -> list[BaseTool]:
    @tool
    def retrieve(query: str, k: int = 4) -> str:
        """Search the local knowledge base for passages related to the query."""
        hits = store.search(query, k=k)
        if not hits:
            return "(no results -- the index is empty; use /ingest first)"
        return "\n\n---\n\n".join(
            f"[{h.metadata.get('source', '?')}]\n{h.page_content}" for h in hits
        )

    @tool
    def calculator(expression: str) -> str:
        """Evaluate a simple arithmetic expression. Supports + - * / // % **."""
        try:
            tree = ast.parse(expression, mode="eval")
            return str(_safe_eval(tree))
        except Exception as e:
            return f"error: {e}"

    @tool
    def file_read(path: str, max_bytes: int = 8192) -> str:
        """Read up to max_bytes from a file path (relative to cwd)."""
        p = Path(path).expanduser().resolve()
        cwd = Path.cwd().resolve()
        if not str(p).startswith(str(cwd)):
            return "error: path escapes cwd"
        if not p.is_file():
            return f"error: not a file: {p}"
        return p.read_bytes()[:max_bytes].decode("utf-8", errors="replace")

    return [retrieve, calculator, file_read]

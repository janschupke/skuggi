"""L1: the three agent tools, as pure functions.

`test_file_read_rejects_sibling_prefix_escape` is the regression test for a real
sandbox escape; the calculator exponent and retrieve-k tests pin denial-of-service
limits on inputs the model itself controls.
"""

from __future__ import annotations

from pathlib import Path

import pytest
from langchain_core.tools import BaseTool

from skuggi.tools import build_tools
from skuggi.vectorstore import Store


def _tool(tools: list[BaseTool], name: str) -> BaseTool:
    return next(tool for tool in tools if tool.name == name)


@pytest.fixture
def file_read(store: Store, sandbox: Path) -> BaseTool:
    return _tool(build_tools(store, root=sandbox), "file_read")


@pytest.fixture
def calculator(store: Store) -> BaseTool:
    return _tool(build_tools(store), "calculator")


# --- file_read: the sandbox boundary ---------------------------------------


def test_file_read_rejects_sibling_prefix_escape(
    file_read: BaseTool, sandbox: Path
) -> None:
    """A sibling directory whose name merely extends the root must be refused.

    With a `str(p).startswith(str(root))` guard, `<root>-secrets` reads as
    "inside" `<root>`. This is the test that fails on the prefix check and
    passes on `Path.is_relative_to`.
    """
    leak = sandbox.parent / f"{sandbox.name}-secrets" / "leak.txt"
    assert leak.is_file(), "fixture should have created the sibling secret"

    out = file_read.invoke({"path": str(leak)})

    assert out.startswith("error:")
    assert "SECRET" not in out


def test_file_read_allows_inside_root(file_read: BaseTool, sandbox: Path) -> None:
    (sandbox / "ok.txt").write_text("hello", encoding="utf-8")
    assert file_read.invoke({"path": str(sandbox / "ok.txt")}) == "hello"


def test_file_read_allows_relative_path(file_read: BaseTool, sandbox: Path) -> None:
    (sandbox / "rel.txt").write_text("relative", encoding="utf-8")
    assert file_read.invoke({"path": "rel.txt"}) == "relative"


def test_file_read_rejects_parent_traversal(file_read: BaseTool) -> None:
    assert file_read.invoke({"path": "../../etc/hosts"}).startswith("error:")


def test_file_read_rejects_symlink_escape(file_read: BaseTool, sandbox: Path) -> None:
    outside = sandbox.parent / "outside.txt"
    outside.write_text("SECRET", encoding="utf-8")
    link = sandbox / "link.txt"
    link.symlink_to(outside)

    out = file_read.invoke({"path": str(link)})

    assert out.startswith("error:")
    assert "SECRET" not in out


def test_file_read_rejects_directory(file_read: BaseTool, sandbox: Path) -> None:
    assert file_read.invoke({"path": str(sandbox)}).startswith("error:")


def test_file_read_truncates_at_max_bytes(file_read: BaseTool, sandbox: Path) -> None:
    (sandbox / "big.txt").write_text("a" * 5000, encoding="utf-8")
    out = file_read.invoke({"path": "big.txt", "max_bytes": 10})
    assert out == "a" * 10


def test_file_read_clamps_absurd_max_bytes(file_read: BaseTool, sandbox: Path) -> None:
    """An LLM-supplied max_bytes must not be able to pull an unbounded read."""
    (sandbox / "big.txt").write_text("b" * 400_000, encoding="utf-8")
    out = file_read.invoke({"path": "big.txt", "max_bytes": 10**9})
    assert len(out) < 400_000


def test_file_read_handles_invalid_utf8(file_read: BaseTool, sandbox: Path) -> None:
    (sandbox / "bad.bin").write_bytes(b"\xff\xfe ok")
    out = file_read.invoke({"path": "bad.bin"})
    assert "ok" in out
    assert not out.startswith("error:")


# --- calculator -------------------------------------------------------------


@pytest.mark.parametrize(
    ("expression", "expected"),
    [
        ("2+2", "4"),
        ("17*23", "391"),
        ("10/4", "2.5"),
        ("7//2", "3"),
        ("7%2", "1"),
        ("2**10", "1024"),
        ("-3+1", "-2"),
        ("+3", "3"),
    ],
)
def test_calculator_arithmetic(
    calculator: BaseTool, expression: str, expected: str
) -> None:
    assert calculator.invoke({"expression": expression}) == expected


@pytest.mark.parametrize(
    "expression",
    [
        "__import__('os').system('true')",
        "().__class__",
        "os.system('true')",
        "x",
        "print(1)",
        "[1,2]",
        "{1:2}",
        "'a'*3",
        "1 if 1 else 2",
        "(lambda: 1)()",
    ],
)
def test_calculator_rejects_non_arithmetic(
    calculator: BaseTool, expression: str
) -> None:
    assert calculator.invoke({"expression": expression}).startswith("error:")


def test_calculator_zero_division(calculator: BaseTool) -> None:
    assert calculator.invoke({"expression": "1/0"}).startswith("error:")


@pytest.mark.timeout(15)
def test_calculator_rejects_huge_exponent(calculator: BaseTool) -> None:
    """`9**9**9` must be refused, not computed.

    Without an exponent cap this hangs the worker -- a tool the model controls
    can freeze the REPL. The timeout makes a regression fail rather than hang.
    """
    assert calculator.invoke({"expression": "9**9**9"}).startswith("error:")


def test_calculator_rejects_complex_result(calculator: BaseTool) -> None:
    """`(-8) ** 0.5` is complex, which violates the declared return type."""
    assert calculator.invoke({"expression": "(-8) ** 0.5"}).startswith("error:")


# --- retrieve ---------------------------------------------------------------


def test_retrieve_reports_empty_index(store: Store) -> None:
    out = _tool(build_tools(store), "retrieve").invoke({"query": "anything"})
    assert "no results" in out


def test_retrieve_clamps_k(store: Store, tmp_path: Path) -> None:
    """An unbounded k would dump the whole index into the prompt."""
    docs = tmp_path / "docs"
    docs.mkdir()
    for i in range(30):
        (docs / f"d{i}.md").write_text(f"passage number {i}", encoding="utf-8")
    store.ingest([docs])

    out = _tool(build_tools(store), "retrieve").invoke({"query": "passage", "k": 10**6})

    assert out.count("---") <= 10


def test_build_tools_exposes_three_documented_tools(store: Store) -> None:
    tools = build_tools(store)
    assert {tool.name for tool in tools} == {"retrieve", "calculator", "file_read"}
    for tool in tools:
        assert tool.description.strip(), f"{tool.name} lost its description"

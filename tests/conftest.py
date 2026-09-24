"""Shared fixtures. Layers L1-L3 run fully offline; L4 (eval) is exempt.

The two autouse fixtures here are load-bearing for isolation. Read the note in
`isolate_credentials` before changing it.
"""

from __future__ import annotations

import io
from collections.abc import Iterator
from pathlib import Path

import httpx
import pytest
from rich.console import Console

from skuggi import codex_chat, providers
from skuggi.vectorstore import Store
from tests.fakes import CountingFakeEmbeddings

_VENDOR_ENV = ("OPENAI_API_KEY", "ANTHROPIC_API_KEY", "OLLAMA_BASE_URL")


def _is_eval(request: pytest.FixtureRequest) -> bool:
    return request.node.get_closest_marker("eval") is not None


@pytest.fixture(autouse=True)
def isolate_credentials(
    request: pytest.FixtureRequest,
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    """Strip provider env vars and redirect the auth.json lookups.

    `providers.AUTH_JSON` and `codex_chat._AUTH_PATH_DEFAULT` are module-level
    constants that are `.expanduser()`-ed at import time, so
    `monkeypatch.setenv("HOME", ...)` does NOT redirect them. Without the two
    `setattr` calls below the suite passes while reading the developer's real
    ~/.codex/auth.json -- a bad outcome for a project whose subject is
    credential files.
    """
    if _is_eval(request):
        return
    for name in _VENDOR_ENV:
        monkeypatch.delenv(name, raising=False)
    for name in list(os_environ_keys()):
        if name.startswith("SKUGGI_"):
            monkeypatch.delenv(name, raising=False)
    absent = tmp_path / "no-such-auth.json"
    monkeypatch.setattr(providers, "AUTH_JSON", absent)
    monkeypatch.setattr(codex_chat, "_AUTH_PATH_DEFAULT", absent)


def os_environ_keys() -> list[str]:
    """Snapshot env var names (indirection keeps the import list short)."""
    import os

    return list(os.environ)


@pytest.fixture(autouse=True)
def no_network(request: pytest.FixtureRequest, monkeypatch: pytest.MonkeyPatch) -> None:
    """Make a forgotten HTTP mock fail loudly instead of reaching the internet."""
    if _is_eval(request):
        return

    def _blocked(*args: object, **kwargs: object) -> object:
        msg = "network access is not allowed in this test layer"
        raise RuntimeError(msg)

    monkeypatch.setattr(httpx.Client, "send", _blocked)
    monkeypatch.setattr(httpx, "post", _blocked)
    monkeypatch.setattr(httpx, "get", _blocked)


@pytest.fixture
def fake_embeddings() -> CountingFakeEmbeddings:
    return CountingFakeEmbeddings()


@pytest.fixture
def store(tmp_path: Path, fake_embeddings: CountingFakeEmbeddings) -> Store:
    return Store(str(tmp_path / "faiss_index"), fake_embeddings)


@pytest.fixture
def sandbox(tmp_path: Path) -> Path:
    """A resolved working directory, with a sibling whose name extends it.

    The sibling is what the prefix-escape regression test reads: with a
    `startswith` guard, `<sandbox>-secrets` passes as "inside" `<sandbox>`.
    Both sides are resolved because on darwin /tmp is a symlink to /private/tmp
    and the tool under test calls `.resolve()` internally.
    """
    work = (tmp_path / "skuggi").resolve()
    work.mkdir()
    secrets = (tmp_path / "skuggi-secrets").resolve()
    secrets.mkdir()
    (secrets / "leak.txt").write_text("SECRET", encoding="utf-8")
    return work


@pytest.fixture
def console_output() -> Iterator[tuple[Console, io.StringIO]]:
    buffer = io.StringIO()
    yield Console(file=buffer, width=100, force_terminal=False), buffer

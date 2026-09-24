"""Shared fixtures and offline-session factories.

The suite is four layers: L1 = tests/unit (pure functions/models), L2 =
tests/integration (real subsystems), L3 = tests/harness (front-ends + AgentCore
offline), L4 = tests/eval (real providers). L1-L3 run fully offline; L4 (eval)
is exempt from the isolation fixtures below.

The three autouse fixtures here are load-bearing for isolation. Read the note in
`isolate_credentials` before changing it. `offline_settings` / `wire_offline_core`
are the shared builders the L3 harness tests use instead of hand-rolling a core.
"""

from __future__ import annotations

import os
import subprocess
from collections.abc import Callable
from pathlib import Path

import httpx
import pytest

from skuggi import codex_chat
from skuggi.config import Settings
from skuggi.core import AgentCore
from skuggi.tools import build_tools
from skuggi.vectorstore import Store
from tests.fakes import CountingFakeEmbeddings, RoleScriptedChatModel

_VENDOR_ENV = ("OPENAI_API_KEY", "ANTHROPIC_API_KEY", "OLLAMA_BASE_URL")

ENGAGEMENT_NAME = "test-eng"

_SCOPE_JSON = """
{{
  "name": "test-eng",
  "timezone": "UTC",
  "authorized_start": "2000-01-01T00:00:00+00:00",
  "authorized_end": "2999-12-31T23:59:59+00:00",
  "target_networks": ["10.0.0.0/8", "192.168.0.0/16"],
  "allowed_hosts": ["localhost", "scanme.example.com"],
  "allowed_tools": ["nmap", "curl", "echo"],
  "allowed_methods": ["recon", "scan"],
  "autonomous": {autonomous}
}}
"""

_REGISTRY_JSON = """
{
  "tools": [
    {"name": "nmap", "binary": "nmap", "method": "scan",
     "version_args": ["--version"], "requires_target": true,
     "install": {"brew": "brew install nmap"}},
    {"name": "curl", "binary": "curl", "method": "recon",
     "version_args": ["--version"], "requires_target": true,
     "install": {"apt": "apt-get install -y curl"}},
    {"name": "echo", "binary": "echo", "method": "recon",
     "requires_target": false, "install": {}}
  ]
}
"""


def offline_settings(tmp_path: Path, *, engagement: str | None = None) -> Settings:
    """Settings that construct without credentials or network (provider=ollama).

    The one place the harness tests describe an offline session: a fake-provider
    Settings with all state redirected under `tmp_path`. `engagement` opts the
    session into a loaded scope (paired with `pentest_configs`).
    """
    return Settings(
        provider="ollama",
        sqlite_path=tmp_path / "sessions.db",
        faiss_path=tmp_path / "faiss",
        history_path=tmp_path / ".repl_history",
        engagement=engagement,
    )


def wire_offline_core(
    core: AgentCore,
    *,
    worker: RoleScriptedChatModel | None = None,
    base_tools_root: Path | None = None,
) -> None:
    """Swap a core's live parts for offline doubles and rebuild tools + graph.

    Replaces the embeddings-backed store and the real LLM with fakes so no test
    reaches localhost:11434 or a provider. `worker` overrides the scripted model
    (default: one plan-worker-critic pass); `base_tools_root` builds only the
    base tools rooted there (for an engagement-less REPL) instead of the pentest
    tool set.
    """
    core.store = Store(core.settings.faiss_path, CountingFakeEmbeddings())
    core.llm = worker or RoleScriptedChatModel(
        worker_replies=["the answer"], critic_replies=["APPROVED: ok"]
    )
    core.tools_list = (
        build_tools(core.store, root=base_tools_root)
        if base_tools_root is not None
        else core.build_tools()
    )
    core.graph = core._build()


def _is_eval(request: pytest.FixtureRequest) -> bool:
    return request.node.get_closest_marker("eval") is not None


@pytest.fixture(autouse=True)
def isolate_credentials(
    request: pytest.FixtureRequest,
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    """Strip provider env vars, redirect auth.json, and escape the repo's .env.

    Three separate leaks have to be closed:

    1. Environment variables, including every SKUGGI_* override.
    2. `Settings` reads a `.env` file relative to the working directory, so a
       test run from the repo root would pick up the developer's real
       OPENAI_API_KEY. chdir to a temp directory closes that, and incidentally
       redirects the default relative ./data paths somewhere disposable.
    3. `codex_chat._AUTH_PATH_DEFAULT` is a module-level constant already
       `.expanduser()`-ed at import time, so setting HOME does NOT redirect it.

    Get any of these wrong and the suite passes while reading real credentials --
    a bad outcome for a project whose subject matter is credential files.
    """
    if _is_eval(request):
        return
    for name in _VENDOR_ENV:
        monkeypatch.delenv(name, raising=False)
    for name in list(os.environ):
        if name.startswith("SKUGGI_"):
            monkeypatch.delenv(name, raising=False)
    absent = tmp_path / "no-such-auth.json"
    monkeypatch.setenv("SKUGGI_CODEX_AUTH_PATH", str(absent))
    monkeypatch.setattr(codex_chat, "_AUTH_PATH_DEFAULT", absent)
    workdir = tmp_path / "cwd"
    workdir.mkdir(exist_ok=True)
    monkeypatch.chdir(workdir)


@pytest.fixture(autouse=True)
def no_network(request: pytest.FixtureRequest, monkeypatch: pytest.MonkeyPatch) -> None:
    """Make a forgotten HTTP mock fail loudly instead of reaching the internet.

    Lifted for tests marked `mock_http`, which install their own transport-level
    interception and would otherwise be blocked before reaching it.
    """
    if _is_eval(request) or request.node.get_closest_marker("mock_http"):
        return

    def _blocked(*args: object, **kwargs: object) -> object:
        msg = "network access is not allowed in this test layer"
        raise RuntimeError(msg)

    monkeypatch.setattr(httpx.Client, "send", _blocked)
    monkeypatch.setattr(httpx, "post", _blocked)
    monkeypatch.setattr(httpx, "get", _blocked)


@pytest.fixture(autouse=True)
def no_subprocess(
    request: pytest.FixtureRequest, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Block real command execution unless a test opts in with `runs_commands`.

    Modeled on `no_network`: the harness's subject matter is running shell
    commands, so a forgotten stub must fail loudly rather than spawn a real
    process. A test that genuinely needs to exec marks itself `runs_commands`.
    """
    if _is_eval(request) or request.node.get_closest_marker("runs_commands"):
        return

    def _blocked(*args: object, **kwargs: object) -> object:
        msg = "subprocess execution is not allowed in this test layer"
        raise RuntimeError(msg)

    monkeypatch.setattr(subprocess, "run", _blocked)
    monkeypatch.setattr("skuggi.execution.run", _blocked)


@pytest.fixture
def pentest_configs() -> Callable[..., Path]:
    """Write a workspace scope.json + the harness tool registry.

    Drops ``engagements/test-eng/scope.json`` and ``configs/tools.json`` under
    the temp cwd `isolate_credentials` chdirs into, so a ``Settings(engagement=
    "test-eng")`` built afterwards finds them at their default paths. Returns the
    workspace directory.
    """

    def write(*, autonomous: bool = False) -> Path:
        workspace = Path("engagements") / ENGAGEMENT_NAME
        workspace.mkdir(parents=True, exist_ok=True)
        (workspace / "scope.json").write_text(
            _SCOPE_JSON.format(autonomous="true" if autonomous else "false"),
            encoding="utf-8",
        )
        configs = Path("configs")
        configs.mkdir(exist_ok=True)
        (configs / "tools.json").write_text(_REGISTRY_JSON, encoding="utf-8")
        return workspace

    return write


@pytest.fixture
def fake_embeddings() -> CountingFakeEmbeddings:
    return CountingFakeEmbeddings()


@pytest.fixture
def store(tmp_path: Path, fake_embeddings: CountingFakeEmbeddings) -> Store:
    return Store(tmp_path / "faiss_index", fake_embeddings)


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

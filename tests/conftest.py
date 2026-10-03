"""Shared fixtures and offline-session factories.

The suite is five layers: L1 = tests/unit (pure functions/models), L2 =
tests/integration (real subsystems), L3 = tests/harness (front-ends + AgentCore
offline), L4 = tests/eval (real providers), L5 = tests/e2e (the real pipeline
against the docker lab). L1-L3 run fully offline; the live layers (L4 eval, L5
e2e) are exempt from the isolation fixtures below -- see `_is_live`.

The three autouse fixtures here are load-bearing for isolation. Read the note in
`isolate_credentials` before changing it. `offline_settings` / `wire_offline_core`
are the shared builders the L3 harness tests use instead of hand-rolling a core.
"""

from __future__ import annotations

import logging
import os
import subprocess
from collections.abc import Callable, Iterator
from pathlib import Path

import httpx
import pytest

from skuggi.agent.core import AgentCore
from skuggi.agent.protocol import CriticResponse, WorkerResponse
from skuggi.common import home
from skuggi.common.paths import ensure_parent
from skuggi.config.config import Settings
from skuggi.persistence.vectorstore import Store
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


def offline_settings(
    tmp_path: Path, *, engagement_root: Path | None = None
) -> Settings:
    """Settings that construct without credentials or network (provider=ollama).

    The one place the harness tests describe an offline session: a fake-provider
    Settings with all state redirected under `tmp_path`. `engagement_root` is an
    explicit engagement directory override; left ``None`` the harness probes the
    current directory (where `pentest_configs` writes its scope).
    """
    return Settings(
        provider="ollama",
        sqlite_path=tmp_path / "sessions.db",
        faiss_path=tmp_path / "faiss",
        history_path=tmp_path / ".repl_history",
        engagement_root=engagement_root,
    )


def wire_offline_core(
    core: AgentCore,
    *,
    worker: RoleScriptedChatModel | None = None,
) -> None:
    """Swap a core's live parts for offline doubles and rebuild the graph.

    Replaces the embeddings-backed store and the real LLM with fakes so no test
    reaches localhost:11434 or a provider. `worker` overrides the scripted model
    (default: one plan-worker-critic pass returning a structured response).
    """
    core.store = Store(core.settings.faiss_path, CountingFakeEmbeddings())
    core.llm = worker or RoleScriptedChatModel(
        worker_replies=[WorkerResponse(summary="the answer")],
        critic_replies=[CriticResponse(approved=True, reason="ok")],
    )
    core.graph = core._build()


def _is_eval(request: pytest.FixtureRequest) -> bool:
    return request.node.get_closest_marker("eval") is not None


def _is_e2e(request: pytest.FixtureRequest) -> bool:
    return request.node.get_closest_marker("e2e") is not None


def _is_live(request: pytest.FixtureRequest) -> bool:
    """A live layer talks to the real world (a provider, or the docker lab).

    Both eval and e2e are exempt from the offline isolation below: eval needs a
    real provider; e2e needs the network block lifted (the lab health poll and
    real curl/nmap against loopback) and the subprocess block lifted (the real
    ``execution.run``). e2e uses a scripted LLM, so it needs no credentials, but
    exempting it from ``isolate_credentials`` also stops the chdir-to-tmp so its
    fixtures can read the repo's ``lab/``/``configs`` by path.
    """
    return _is_eval(request) or _is_e2e(request)


@pytest.fixture(autouse=True)
def isolate_credentials(
    request: pytest.FixtureRequest,
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    """Strip provider env vars, redirect both homes and auth.json, escape any .env.

    Four separate leaks have to be closed:

    1. Environment variables, including every SKUGGI_* override.
    2. The config and data homes (`skuggi.home`). `Settings`' storage defaults are
       ABSOLUTE -- they resolve under ~/.config/skuggi and ~/.local/share/skuggi,
       not under the working directory -- so chdir does NOT redirect them and a
       test run would read the developer's real config.json and write their real
       sessions.db. Pointing SKUGGI_CONFIG_HOME/SKUGGI_DATA_HOME at tmp_path is
       what closes this, and it closes the `<config home>/env` secrets file with
       them (the successor to the cwd-relative `.env` this note used to describe).
    3. `codex_chat`'s fallback auth.json path, resolved at call time from
       `SKUGGI_CODEX_AUTH_PATH` (so setting that env var below redirects it;
       no module monkeypatch needed).
    4. chdir is still required: the engagement root defaults to the current
       directory (cwd probe / `set engagement` with no path), so without it a test
       could discover or scaffold a `scope.json` tree in the repo.

    Get any of these wrong and the suite passes while reading real credentials --
    a bad outcome for a project whose subject matter is credential files. Leak 2
    is the one the suite cannot report on itself: nothing fails, the tests simply
    read and write the wrong files. `make check` is not proof here; an empty
    `ls ~/.config/skuggi ~/.local/share/skuggi` after a run is.
    """
    if _is_live(request):
        return
    for name in _VENDOR_ENV:
        monkeypatch.delenv(name, raising=False)
    for name in list(os.environ):
        if name.startswith("SKUGGI_"):
            monkeypatch.delenv(name, raising=False)
    # Set after the SKUGGI_* sweep above, which would otherwise strip them.
    monkeypatch.setenv(home.CONFIG_HOME_ENV, str(tmp_path / "config-home"))
    monkeypatch.setenv(home.DATA_HOME_ENV, str(tmp_path / "data-home"))
    absent = tmp_path / "no-such-auth.json"
    monkeypatch.setenv("SKUGGI_CODEX_AUTH_PATH", str(absent))
    workdir = tmp_path / "cwd"
    workdir.mkdir(exist_ok=True)
    monkeypatch.chdir(workdir)


@pytest.fixture(autouse=True)
def no_network(request: pytest.FixtureRequest, monkeypatch: pytest.MonkeyPatch) -> None:
    """Make a forgotten HTTP mock fail loudly instead of reaching the internet.

    Lifted for tests marked `mock_http`, which install their own transport-level
    interception and would otherwise be blocked before reaching it.
    """
    if _is_live(request) or request.node.get_closest_marker("mock_http"):
        return

    def _blocked(*args: object, **kwargs: object) -> object:
        msg = "network access is not allowed in this test layer"
        raise RuntimeError(msg)

    monkeypatch.setattr(httpx.Client, "send", _blocked)
    monkeypatch.setattr(httpx.AsyncClient, "send", _blocked)
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
    if _is_live(request) or request.node.get_closest_marker("runs_commands"):
        return

    def _blocked(*args: object, **kwargs: object) -> object:
        msg = "subprocess execution is not allowed in this test layer"
        raise RuntimeError(msg)

    monkeypatch.setattr(subprocess, "run", _blocked)
    monkeypatch.setattr("skuggi.common.execution.run", _blocked)


@pytest.fixture(autouse=True)
def reset_logging() -> Iterator[None]:
    """Snapshot and restore the root logger around every test.

    ``logs.setup_logging`` configures the *root* logger -- global, process-wide
    state. A test (or any entry-point ``main`` a test drives) that calls it would
    otherwise leave a ``RotatingFileHandler`` open on that test's ``tmp_path``,
    which is then deleted: later tests inherit a handler pointing at a vanished
    directory, and the leak is exactly the kind the ``isolate_credentials`` note
    warns about -- nothing fails, the wrong files are touched. Restoring the
    handler list and level after each test keeps logging setup isolated.
    """
    root = logging.getLogger()
    saved_handlers = root.handlers[:]
    saved_level = root.level
    try:
        yield
    finally:
        for handler in root.handlers[:]:
            if handler not in saved_handlers:
                handler.close()
                root.removeHandler(handler)
        for handler in saved_handlers:
            if handler not in root.handlers:
                root.addHandler(handler)
        root.setLevel(saved_level)


@pytest.fixture
def pentest_configs() -> Callable[..., Path]:
    """Write a workspace scope.json + the harness tool registry.

    The engagement IS the current directory: the scope lands at ``./scope.json``
    (the temp cwd `isolate_credentials` chdirs into), and the registry into the
    config home that same fixture redirects. A default ``offline_settings`` built
    afterwards adopts the engagement by probing cwd. Returns the workspace dir.
    """

    def write(*, autonomous: bool = False) -> Path:
        workspace = Path.cwd()
        (workspace / "scope.json").write_text(
            _SCOPE_JSON.format(autonomous="true" if autonomous else "false"),
            encoding="utf-8",
        )
        registry = ensure_parent(home.config_home() / "tools.json")
        registry.write_text(_REGISTRY_JSON, encoding="utf-8")
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

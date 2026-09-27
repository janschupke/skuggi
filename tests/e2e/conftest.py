"""L5 fixtures: drive skuggi's real pipeline against the running docker lab.

This is the only layer that executes real commands against a real target. The
worker is *scripted* (no LLM, deterministic) but everything downstream is the
production path: the engagement guard, the tool registry, the ledger, the real
``skuggi.execution.run`` subprocess, and real ``curl``/``nmap`` against the lab.

Reachability is loopback-primary: the lab publishes ``127.0.0.1:<port>`` on
every platform, so that is the default target; the in-network IP ``192.0.2.10``
is exercised only when it is directly routable (``ip_routable``). The whole
layer skips cleanly when the lab is not up -- mirroring how eval skips on a
missing provider -- and never brings the lab up unless ``SKUGGI_E2E_COMPOSE_UP``
is set (a ``docker compose down -v`` would drop the operator's lab DB volume).
"""

from __future__ import annotations

import os
import shutil
import socket
import subprocess
import time
from collections.abc import Iterator
from dataclasses import dataclass
from pathlib import Path

import httpx
import pytest

from skuggi.core import AgentCore
from skuggi.ledger import CommandRow
from skuggi.protocol import CriticResponse, FindingDraft, WorkerResponse
from tests.fakes import RoleScriptedChatModel
from tests.support import REPO_ROOT, engaged_core, wire_offline_llm

LAB_DIR = REPO_ROOT / "tests" / "e2e" / "fixtures" / "lab"
LAB_COMPOSE = LAB_DIR / "docker-compose.yml"
LAB_IP = "192.0.2.10"
_DEFAULT_HTTP_PORT = 8080


@dataclass(frozen=True)
class Lab:
    """A reachable lab: the loopback base URL plus its host and port."""

    host: str
    port: int

    @property
    def base_url(self) -> str:
        return f"http://{self.host}:{self.port}"


def _compose(*args: str) -> subprocess.CompletedProcess[str]:
    argv = ["docker", "compose", "-f", str(LAB_COMPOSE), *args]
    return subprocess.run(  # noqa: S603 -- docker is on PATH, shell=False
        argv, capture_output=True, text=True, check=False
    )


def _discover_http_port() -> int:
    """The host port the lab publishes for the web container's :80.

    ``docker compose port`` is the source of truth (survives a collision remap);
    fall back to ``lab/.env`` then ``lab/.env.example`` then the documented 8080.
    """
    if shutil.which("docker"):
        proc = _compose("port", "web", "80")
        tail = proc.stdout.strip().rsplit(":", 1)
        if proc.returncode == 0 and len(tail) == 2 and tail[1].isdigit():
            return int(tail[1])
    for env_file in (LAB_DIR / ".env", LAB_DIR / ".env.example"):
        if env_file.is_file():
            for line in env_file.read_text(encoding="utf-8").splitlines():
                key, _, value = line.partition("=")
                if key.strip() == "WEB_HTTP_PORT" and value.strip().isdigit():
                    return int(value.strip())
    return _DEFAULT_HTTP_PORT


def _healthy(base_url: str, *, attempts: int = 10, delay: float = 1.0) -> bool:
    """Poll the lab's root the way the compose healthcheck does."""
    for _ in range(attempts):
        try:
            if httpx.get(base_url + "/", timeout=2.0).is_success:
                return True
        except httpx.HTTPError:
            pass
        time.sleep(delay)
    return False


def ip_routable(ip: str = LAB_IP, port: int = 80) -> bool:
    """Whether the in-network lab IP is directly reachable (Linux / macOS+WG)."""
    try:
        with socket.create_connection((ip, port), timeout=1.0):
            return True
    except OSError:
        return False


@pytest.fixture(scope="session")
def lab() -> Iterator[Lab]:
    """The running lab, or a clean skip of the whole layer when it is down."""
    bring_up = os.environ.get("SKUGGI_E2E_COMPOSE_UP") == "1"
    if bring_up:
        if not shutil.which("docker"):
            pytest.skip("SKUGGI_E2E_COMPOSE_UP set but docker is not installed")
        up = _compose("up", "-d", "--wait")
        if up.returncode != 0:
            pytest.skip(f"lab did not come up: {up.stderr.strip()[:200]}")
    port = _discover_http_port()
    target = Lab(host="127.0.0.1", port=port)
    if not _healthy(target.base_url):
        if bring_up:
            _compose("down", "-v")
        pytest.skip(
            f"skuggi lab is not reachable at {target.base_url} -- bring it up: "
            "`docker compose -f tests/e2e/fixtures/lab/docker-compose.yml up -d --wait`"
        )
    try:
        yield target
    finally:
        if bring_up:
            _compose("down", "-v")


def _e2e_scope(name: str) -> dict[str, object]:
    """A scope authorizing the loopback host and the lab network.

    ``127.0.0.0/8`` in ``target_networks`` is load-bearing: the guard matches a
    bare IP by network membership, not against ``allowed_hosts``. No port is
    encoded -- the guard strips it from the URL host.
    """
    return {
        "name": name,
        "timezone": "UTC",
        "authorized_start": "2000-01-01T00:00:00+00:00",
        "authorized_end": "2999-12-31T23:59:59+00:00",
        "daily_windows": [{"start": "00:00:00", "end": "23:59:59"}],
        "target_networks": ["127.0.0.0/8", "192.0.2.0/24"],
        "allowed_hosts": ["web.lab"],
        "allowed_tools": [
            "nmap",
            "curl",
            "gobuster",
            "ffuf",
            "sqlmap",
            "hydra",
            "john",
        ],
        "allowed_methods": [
            "recon",
            "scan",
            "enumerate",
            "bruteforce",
            "crack",
            "exploit",
        ],
        "autonomous": False,
    }


class Runner:
    """Runs real autonomous engagements against the lab, one core per call.

    ``run`` scripts the worker to propose ``commands`` in order (each really
    executed via the production pipeline), records any ``findings``, then stops,
    and returns the recorded ``CommandRow``s. ``core`` exposes the most recent
    core so a test can reach the ledger, the report, or the findings directly.
    """

    def __init__(self, tmp_path: Path) -> None:
        self._tmp_path = tmp_path
        self.cores: list[AgentCore] = []

    @property
    def core(self) -> AgentCore:
        return self.cores[-1]

    def run(
        self,
        *commands: str,
        findings: tuple[FindingDraft, ...] = (),
        timeout_s: float = 60.0,
    ) -> list[CommandRow]:
        core = engaged_core(
            self._tmp_path,
            _e2e_scope(f"lab-e2e-{len(self.cores)}"),
            command_timeout_s=timeout_s,
        )
        self.cores.append(core)
        replies = [WorkerResponse(command=c, summary=f"run {c}") for c in commands]
        # Findings ride the final response; the executor links them to the last
        # recorded command.
        replies.append(WorkerResponse(summary="done", done=True, findings=findings))
        worker = RoleScriptedChatModel(
            worker_replies=replies,
            critic_replies=[CriticResponse(approved=True, reason="ok")],
        )
        wire_offline_llm(core, worker)
        core.set_autonomous(True)
        list(core.turn("engage the lab"))
        return core.ledger.commands_for(core.session_id)


@pytest.fixture
def engage(tmp_path: Path, lab: Lab) -> Iterator[Runner]:
    """A :class:`Runner` bound to the running lab; closes every core on teardown."""
    runner = Runner(tmp_path)
    yield runner
    for core in runner.cores:
        core.close()


def require_tool(binary: str) -> None:
    """Skip a case whose tool is not installed on this host."""
    if shutil.which(binary) is None:
        pytest.skip(f"{binary} is not installed on this host")

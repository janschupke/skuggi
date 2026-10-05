"""The opt-in container execution backend: run a tool in a throwaway container.

``HostBackend`` runs a cleared command as a direct host subprocess -- fine for a
single-operator box, but a hostile target's response or a tool bug then executes
with the operator's uid and host network. ``ContainerBackend`` runs the same argv
inside a one-shot ``docker``/``podman`` container that is dropped on exit, giving
real OS-level isolation the host path cannot: a read-only root filesystem, every
Linux capability dropped, no privilege escalation, CPU/memory/pid ceilings, a
non-root uid, and only the engagement workspace bind-mounted writable.

It is a thin wrapper: it builds the ``run`` argv and delegates to
``execution.run`` (the container runtime is itself just another host subprocess,
bounded by the same wall-clock timeout and output cap), so there is one capture
path and the backend stays unit-testable without a live daemon.

Network: ``network`` is passed straight to ``--network``. The safe default is
``none`` (no egress at all); an engagement that must reach its in-scope targets
uses an operator-provisioned, egress-filtered network name here -- building the
firewall rules is a provisioning step, not something the backend fabricates.
"""

from __future__ import annotations

import os
from collections.abc import Callable, Mapping, Sequence
from dataclasses import dataclass, field
from pathlib import Path

from skuggi.common import execution
from skuggi.common.execution import CommandResult

# The capture seam: ``execution.run`` in production, a fake in a test. Typed
# loosely (``...``) because only the keyword set the backend passes matters.
RunFn = Callable[..., CommandResult]


@dataclass(frozen=True, slots=True)
class ContainerConfig:
    """How the container backend launches a tool (operator configuration)."""

    image: str
    runtime: str = "docker"  # or "podman"
    network: str = "none"  # --network; "none" = no egress (safe default)
    cpus: str = "2"  # --cpus
    memory: str = "2g"  # --memory
    pids_limit: int = 512  # --pids-limit


@dataclass(frozen=True, slots=True)
class ContainerBackend:
    """Run a cleared command inside a throwaway, locked-down container."""

    config: ContainerConfig
    run_fn: RunFn | None = field(default=None)  # test seam; defaults to execution.run

    def _runner(self) -> RunFn:
        return execution.run if self.run_fn is None else self.run_fn

    def _wrap(
        self,
        argv: Sequence[str],
        cwd: Path,
        env: Mapping[str, str] | None,
    ) -> list[str]:
        """Build the ``<runtime> run ...`` argv that launches `argv` sandboxed."""
        c = self.config
        mount = str(cwd.resolve())
        wrapped = [
            c.runtime,
            "run",
            "--rm",
            "--network",
            c.network,
            "--read-only",  # immutable root fs
            "--tmpfs",
            "/tmp",  # a writable scratch that vanishes with the container  # noqa: S108
            "--cap-drop",
            "ALL",  # no Linux capabilities
            "--security-opt",
            "no-new-privileges",  # a setuid tool cannot regain privilege
            "--cpus",
            c.cpus,
            "--memory",
            c.memory,
            "--pids-limit",
            str(c.pids_limit),
            "-v",
            f"{mount}:{mount}:rw",  # only the workspace is writable
            "-w",
            mount,
        ]
        if hasattr(os, "getuid"):  # run as the invoking uid, never root in-container
            wrapped += ["-u", f"{os.getuid()}:{os.getgid()}"]
        for key, value in (env or {}).items():
            wrapped += ["-e", f"{key}={value}"]
        wrapped.append(c.image)
        wrapped += list(argv)
        return wrapped

    def run(
        self,
        argv: Sequence[str],
        *,
        timeout: float,
        cwd: Path,
        env: Mapping[str, str] | None = None,
        display_command: str | None = None,
    ) -> CommandResult:
        """Run `argv` in a throwaway container, captured like any host command."""
        wrapped = self._wrap(argv, cwd, env)
        runner = self._runner()
        # The container runtime invocation itself gets a minimal host env (it needs
        # PATH/HOME/DOCKER_HOST, not the tool's env, which is injected via -e above).
        result: CommandResult = runner(
            wrapped,
            timeout=timeout,
            cwd=cwd,
            env=execution.safe_env(),
            display_command=display_command
            if display_command is not None
            else " ".join(argv),
        )
        return result

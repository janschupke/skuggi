"""The engagement plane: scope, workspace, registries, and the ledger/vault.

Owns everything scoped to *which engagement* is loaded -- the workspace layout and
workspace, the parsed scope, the tool/command registries, and the per-engagement
ledger and secret vault (it opens them in ``__init__``, closes them in ``close()``,
and reopens them in ``adopt_engagement`` for a hot engagement switch). It also owns
the GraphDeps block-builders that derive from engagement state. A sibling
sub-component: it reads session scalars (``session_id``/``mode``) and mutates
``settings`` through ``core``, and signals ``core.rebuild_graph()`` after any change.
"""

from __future__ import annotations

import json
import uuid
from contextlib import AbstractContextManager
from pathlib import Path
from typing import TYPE_CHECKING

from pydantic import ValidationError

from skuggi.agent import awareness
from skuggi.common.logs import get_logger
from skuggi.config.configs import (
    ConfigError,
    InvalidScopeError,
    load_commands,
    load_env,
    load_layout,
    load_registry,
    load_scope,
    write_env,
)
from skuggi.engagement import datafiles
from skuggi.engagement.engagement import EngagementConfig, ThreatModel
from skuggi.engagement.runtime_env import EngagementEnv, write_runtime_env
from skuggi.engagement.workspace import (
    Workspace,
    WorkspaceLayout,
    has_engagement,
    safe_engagement_name,
)
from skuggi.persistence import ledger as ledger_mod
from skuggi.security.policy import RedactionPolicy
from skuggi.security.vault import SecretVault, open_vault
from skuggi.tooling.commands import CommandRegistry
from skuggi.tooling.registry import ToolRegistry

if TYPE_CHECKING:
    from skuggi.agent.core import AgentCore

log = get_logger(__name__)


class EngagementManager:
    """Owns the engagement scope, registries and ledger/vault for one session."""

    def __init__(self, core: AgentCore) -> None:
        self._core = core
        self.layout = self._load_layout()
        self.workspace = self._open_workspace()
        self.engagement = self._load_scope()
        self.env = self._load_env()
        self.registry = self._load_registry()
        self.commands = self._load_commands()
        self._ledger_ctx = ledger_mod.open_ledger(self._ledger_path())
        self.ledger = self._ledger_ctx.__enter__()
        # The per-engagement secret vault (reversible redaction). Opened with the
        # ledger and torn down with it on a reload; None in agent-only mode.
        self._vault_ctx, self.vault = self._open_vault()
        self.ledger.start_session(
            self._core.session_id,
            engagement_name=self.engagement.name if self.engagement else "(none)",
            mode=self._core.mode,
        )
        self._ensure_threat_model_version()

    def close(self) -> None:
        """Tear down the vault then the ledger (mirrors how they were opened)."""
        if self._vault_ctx is not None:
            self._vault_ctx.__exit__(None, None, None)
        self._ledger_ctx.__exit__(None, None, None)

    # ----- config + workspace loaders ----------------------------------------

    def _load_layout(self) -> WorkspaceLayout:
        try:
            return load_layout(self._core.settings.layout_path)
        except ConfigError as exc:
            log.warning("invalid workspace layout, using defaults: %s", exc)
            self._core.warnings.append(
                f"invalid workspace layout, using defaults: {exc}"
            )
            return WorkspaceLayout()

    def _open_workspace(self) -> Workspace | None:
        root = self._resolve_engagement_root()
        if root is None:
            # Descriptive only; the front-end appends a grammar-correct hint to
            # create one (an env var is not the operator-facing answer).
            log.info("no engagement selected; running agent-only")
            self._core.warnings.append("no engagement selected; running agent-only")
            return None
        ws = Workspace.at(root, layout=self.layout)
        ws.ensure()
        return ws

    def _resolve_engagement_root(self) -> Path | None:
        """Which directory is the active engagement: an explicit override, else cwd.

        Nothing is auto-persisted -- an engagement is cwd-scoped. An explicit
        ``engagement_root`` (env/JSON) is honoured when it holds a ``scope.json``;
        otherwise recovery is a probe of the current directory. Returns ``None``
        for agent-only (no override and no scope.json in cwd).
        """
        configured = self._core.settings.engagement_root
        if configured is not None and has_engagement(configured, self.layout):
            return configured
        cwd = Path.cwd()
        if has_engagement(cwd, self.layout):
            return cwd
        return None

    def _load_scope(self) -> EngagementConfig | None:
        if self.workspace is None:
            return None
        try:
            return load_scope(self.workspace.scope_path)
        except ConfigError as exc:
            log.warning("no engagement loaded: %s", exc)
            self._core.warnings.append(f"no engagement loaded: {exc}")
            return None

    def _load_env(self) -> EngagementEnv:
        """Load the engagement's runtime vars, seeding a legacy ``primary_target``.

        Empty when agent-only. When ``env.json`` does not yet exist, a legacy
        ``primary_target`` still in ``scope.json`` (the field moved out of scope)
        is carried into the env ``target`` once -- best-effort, in memory; the
        first ``set target``/``listener``/``wordlist`` persists ``env.json``.
        """
        if self.workspace is None:
            return EngagementEnv()
        path = self.workspace.env_path
        if not path.is_file():
            return self._seed_env_from_legacy_scope() or EngagementEnv()
        try:
            return load_env(path)
        except ConfigError as exc:
            log.warning("no engagement env loaded: %s", exc)
            self._core.warnings.append(f"no engagement env loaded: {exc}")
            return EngagementEnv()

    def _seed_env_from_legacy_scope(self) -> EngagementEnv | None:
        """An ``EngagementEnv`` carrying a legacy scope ``primary_target``, or None."""
        if self.workspace is None:  # pragma: no cover -- guarded by the caller
            return None
        try:
            raw = json.loads(self.workspace.scope_path.read_text(encoding="utf-8"))
        except (OSError, ValueError):
            return None
        legacy = raw.get("primary_target") if isinstance(raw, dict) else None
        return EngagementEnv(target=str(legacy)) if legacy else None

    def effective_target(self) -> str | None:
        """The current target: the manual env value, else the scope default."""
        default = (
            self.engagement.resolve_target() if self.engagement is not None else None
        )
        return self.env.effective_target(default)

    def apply_env(self, env: EngagementEnv) -> None:
        """Persist the engagement's runtime vars in place and refresh the shell file.

        Edited in place -- no new session. ``env.json`` survives a restart; the
        shell-sourced runtime file is rewritten so a live shell sees the change,
        and the graph is rebuilt so the redaction allow-list tracks the target.
        """
        self.env = env
        if self.workspace is not None:
            write_env(self.workspace.env_path, env)
        self.refresh_runtime_env()
        self._core.rebuild_graph()

    def refresh_runtime_env(self) -> None:
        """Rewrite the shell-sourced runtime env file, if a session path is set.

        The path is set only inside the ``skuggi`` shell (by ``shell.main``);
        ``None`` in the REPL / tests / agent-only, where no wrapped shell sources
        it. So mutating env vars is a no-op on the file outside a live shell.
        """
        path = self._core.runtime_env_path
        if path is None:
            return
        default = (
            self.engagement.resolve_target() if self.engagement is not None else None
        )
        write_runtime_env(path, self.env, default)

    def _load_registry(self) -> ToolRegistry:
        try:
            return load_registry(self._core.settings.registry_path)
        except ConfigError as exc:
            log.warning("no tool registry loaded: %s", exc)
            self._core.warnings.append(f"no tool registry loaded: {exc}")
            return ToolRegistry()

    def _load_commands(self) -> CommandRegistry:
        try:
            return load_commands(self._core.settings.commands_path)
        except ConfigError as exc:
            log.warning("no command aliases loaded: %s", exc)
            self._core.warnings.append(f"no command aliases loaded: {exc}")
            return CommandRegistry()

    def _ledger_path(self) -> Path:
        if self.workspace is not None:
            return self.workspace.ledger_path
        return self._core.settings.sqlite_path.parent / "ledger.db"

    def _open_vault(
        self,
    ) -> tuple[AbstractContextManager[SecretVault] | None, SecretVault | None]:
        """Open the engagement's secret vault, or (None, None) in agent-only mode.

        The vault only makes sense with a workspace: it stores secrets *this
        engagement* discovered, next to its ledger. Agent-only mode has nowhere
        to scope it and no commands to run, so redaction there is one-way.
        """
        if self.workspace is None:
            return None, None
        ctx = open_vault(self.workspace.vault_path)
        return ctx, ctx.__enter__()

    def reload_registries(self) -> None:
        """Rebuild the registry/commands/graph from disk after a template write."""
        self.registry = self._load_registry()
        self.commands = self._load_commands()
        self._core.rebuild_graph()

    # ----- GraphDeps block-builders + scope-derived seams --------------------

    def datafiles_block(self) -> str:
        """The metadata-only inventory of tool-input/evidence/loot files.

        Lets the agent reference a wordlist or evidence file by path without ever
        seeing its contents. Empty in agent-only mode (no workspace).
        """
        if self.workspace is None:
            return ""
        ws = self.workspace
        files = datafiles.list_datafiles(
            [
                (ws.inputs_dir, "input"),
                (ws.evidence_dir, "evidence"),
                (ws.loot_dir, "loot"),
            ],
            ws.root,
        )
        return datafiles.render_datafiles(files)

    def system_facts_block(self) -> str:
        """The host-awareness block (OS, installers, scoped tool presence).

        Rebuilt with the graph (on config/engagement changes, not per turn), so a
        mid-session install is reflected on the next rebuild.
        """
        return awareness.system_facts_block(
            self.registry,
            self.engagement,
            source=self._core.settings.tool_source,
            managed_dir=self._core.settings.managed_tools_dir,
        )

    def harness_catalogue_block(self) -> str:
        """The harness command catalogue (verbs/nouns + saved cmd aliases)."""
        return awareness.harness_catalogue_block(self.commands.names())

    def redaction_policy(self) -> RedactionPolicy:
        """The redaction policy for this session, allow-listing in-scope identifiers.

        The agent has to reason about its own targets, so the engagement's name,
        hosts, networks and the current (effective) target pass through
        un-redacted; everything else a detector flags is scrubbed. The effective
        target covers a manually-set ``target`` env var, so an operator-chosen
        host is never scrubbed out of reports/model context.
        """
        if self.engagement is None:
            return RedactionPolicy()
        allow: set[str] = {
            self.engagement.name,
            *self.engagement.allowed_hosts,
            *(str(net) for net in self.engagement.target_networks),
        }
        target = self.effective_target()
        if target:
            allow.add(target)
        return RedactionPolicy.from_scope(allow=allow)

    @property
    def reports_dir(self) -> Path:
        """Where ``write_report`` writes -- the workspace, or ./data as fallback."""
        if self.workspace is not None:
            return self.workspace.reports_dir
        return self._core.settings.sqlite_path.parent / "reports"

    def recon_cwd(self) -> Path | None:
        """The recon working directory for executed commands (None = agent-only)."""
        return self.workspace.recon_dir if self.workspace is not None else None

    @property
    def autonomous(self) -> bool:
        """Whether autonomous command execution is armed."""
        return self.engagement is not None and self.engagement.autonomous

    def set_autonomous(self, want: bool | None) -> bool:
        """Toggle autonomous execution; returns the new state.

        Raises ValueError when no engagement is loaded (there is nothing to arm).
        """
        if self.engagement is None:
            msg = "no engagement loaded"
            raise ValueError(msg)
        target = (not self.engagement.autonomous) if want is None else want
        self.engagement = self.engagement.model_copy(update={"autonomous": target})
        self._core.rebuild_graph()
        return target

    # ----- engagement data ---------------------------------------------------

    def describe_engagement(self) -> str | None:
        """The loaded scope summary, or None when no engagement is loaded."""
        return self.engagement.describe() if self.engagement is not None else None

    def create_engagement(
        self, raw: dict[str, object], *, root: Path | None = None
    ) -> EngagementConfig:
        """Validate a scope dict, persist it to the engagement's scope.json, adopt it.

        Raises ``ConfigError`` if the scope does not validate (the wizard shows
        the reason and re-asks). The scope is written to ``scope.json`` directly
        inside `root` -- the active engagement root, or the current directory when
        none is open -- and hot-adopted via ``adopt_engagement``.
        """
        try:
            scope = EngagementConfig.model_validate(raw)
        except ValidationError as exc:
            keys = frozenset(
                str(err["loc"][0]) for err in exc.errors() if err.get("loc")
            )
            summary = "; ".join(
                f"{'.'.join(str(p) for p in err.get('loc', ()))}: {err['msg']}"
                for err in exc.errors()
            )
            raise InvalidScopeError(summary or str(exc), keys) from exc
        # Past pydantic, the tree still has to be writable; a disk error must
        # re-ask rather than crash the wizard. The name no longer names a
        # directory, but it is still the ledger/report label, so an unusable one
        # (empty, all-punctuation) is re-asked rather than left to corrupt a slug.
        target = root if root is not None else self._active_root()
        try:
            safe_engagement_name(scope.name)
            workspace = Workspace.at(target, layout=self.layout)
            workspace.ensure()
            workspace.scope_path.write_text(
                scope.model_dump_json(indent=2), encoding="utf-8"
            )
            return self.adopt_engagement(target)
        except (ValueError, OSError) as exc:
            raise InvalidScopeError(str(exc), frozenset({"name"})) from exc

    def _active_root(self) -> Path:
        """The engagement root scope writes target: the open workspace, else cwd."""
        return self.workspace.root if self.workspace is not None else Path.cwd()

    def adopt_engagement(self, root: Path) -> EngagementConfig:
        """Switch the active engagement to the one rooted at `root`, hot-reloading.

        Reopens the workspace and scope, reopens the ledger at the new
        engagement's path under a fresh session, and rebuilds the tool set and
        graph -- so a running session reflects the new boundary with no restart.
        Raises ``ConfigError`` if the scope is missing or invalid.
        """
        # In-memory only, deliberately NOT persisted to config.json: an
        # engagement is cwd-scoped, so a machine-global pointer would be a
        # category error. Restart recovery is a cwd probe in
        # ``_resolve_engagement_root``; an explicit env/JSON ``engagement_root``
        # still overrides.
        self._core.settings = self._core.settings.model_copy(
            update={"engagement_root": root}
        )
        self.workspace = self._open_workspace()
        if self.workspace is None:  # pragma: no cover -- root holds scope here
            msg = f"could not open workspace at {str(root)!r}"
            raise ConfigError(msg)
        self.engagement = load_scope(self.workspace.scope_path)
        self.env = self._load_env()

        self._ledger_ctx.__exit__(None, None, None)
        self._ledger_ctx = ledger_mod.open_ledger(self._ledger_path())
        self.ledger = self._ledger_ctx.__enter__()
        # Swap the vault to the new engagement's, mirroring the ledger reload.
        if self._vault_ctx is not None:
            self._vault_ctx.__exit__(None, None, None)
        self._vault_ctx, self.vault = self._open_vault()
        self._core.session_id = str(uuid.uuid4())
        self.ledger.start_session(
            self._core.session_id,
            engagement_name=self.engagement.name,
            mode=self._core.mode,
        )
        self._ensure_threat_model_version()

        self.refresh_runtime_env()  # the new engagement's vars reach a live shell
        self._core.rebuild_graph()
        return self.engagement

    def _threat_model_snapshot(self) -> str:
        """The active engagement's threat model as JSON ('' when none is set)."""
        tm = self.engagement.threat_model if self.engagement else None
        return tm.model_dump_json() if tm else ""

    def _ensure_threat_model_version(self) -> None:
        """Record version 1 of the threat model if the ledger has none yet.

        Later changes are versioned by ``update_threat_model`` (the supported path);
        a hand-edited scope.json is not auto-versioned.
        """
        if self.ledger.current_threat_model_version() == 0:
            self.ledger.record_threat_model(
                self._threat_model_snapshot(), note="(initial)"
            )

    def update_threat_model(
        self, threat_model: ThreatModel | None, *, note: str = ""
    ) -> int:
        """Set the engagement's threat model, version the change, hot-reload scope.

        Persists the new model to scope.json (so it survives a restart), records a
        threat-model version with ``note`` (the change log), and returns the new
        version. Findings scored under an earlier version are now flagged outdated
        until rescored. Requires an active engagement.
        """
        if self.engagement is None:
            msg = "no engagement loaded; cannot set a threat model"
            raise ConfigError(msg)
        # Modify the engagement in place (like set_autonomous) rather than
        # reloading: a threat-model change must not start a new session or orphan
        # this session's findings from the version it bumps.
        self.engagement = self.engagement.model_copy(
            update={"threat_model": threat_model}
        )
        if self.workspace is not None:
            self.workspace.scope_path.write_text(
                self.engagement.model_dump_json(indent=2), encoding="utf-8"
            )
        self._core.rebuild_graph()  # so GraphDeps carries the new threat model
        return self.ledger.record_threat_model(self._threat_model_snapshot(), note=note)

    def apply_engagement_scope(self, engagement: EngagementConfig) -> None:
        """Persist an edited scope in place and hot-reload it (like the threat model).

        The caller (``ScopeController``) has already re-validated ``engagement``.
        Edited in place -- no new session -- so this session's findings are not
        orphaned; the graph is rebuilt so its guard/brief see the new scope.
        """
        self.engagement = engagement
        if self.workspace is not None:
            self.workspace.scope_path.write_text(
                engagement.model_dump_json(indent=2), encoding="utf-8"
            )
        self._core.rebuild_graph()

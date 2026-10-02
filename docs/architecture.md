# Architecture

skuggi is a pentest harness layered on a LangChain + LangGraph agent. The
headless core ([src/skuggi/core.py](../src/skuggi/core.py), `AgentCore`) owns a
session — engagement scope, tool registry, ledger, checkpointer, the compiled
graph — and streams turn events. Two front-ends render it: the Rich +
prompt_toolkit REPL ([src/skuggi/tui.py](../src/skuggi/tui.py)) and the
wrapped-shell daemon ([src/skuggi/daemon.py](../src/skuggi/daemon.py)). Neither
holds agent logic; `AgentCore.turn` yields `TurnEvent`s (reset / status / token
/ final) so the same stream drives a Rich `Live` pane and a plain socket alike.

## The structured protocol

Every LLM interaction is a strict structured exchange, defined in
[src/skuggi/protocol.py](../src/skuggi/protocol.py). The harness builds a
`RequestContext` — conversation history, the engagement scope + `stance`, the
current methodology `Phase`, prior findings and the commands run so far this turn
— and `render_request` turns it into one labelled block. Each node returns a
validated pydantic response (`PlannerResponse`, `WorkerResponse`,
`CriticResponse`) obtained through the single `structured_invoke` seam: native
`with_structured_output` where the provider supports it, and a JSON contract +
one repair retry on the tool-less chatgpt path. `render_response` lays a
`WorkerResponse` out deterministically, so the operator only ever sees model text
inside fields the harness placed — never raw model output pasted to a CLI. All
prompt text lives in [src/skuggi/prompts.py](../src/skuggi/prompts.py).

## The graph

```
START → planner → retriever → worker → executor ──┬── worker (loops back, autonomous)
                                                  │
                                                  └── critic ─┬─ approved → respond → END
                                                              ├─ max revs → respond → END
                                                              └─ else → bump → planner
```

- **planner** — reads the conversation, request, phase, findings and any prior
  critique, and returns a `PlannerResponse` (numbered plan + a phase judgement).
  It advances the phase at most one step per turn (`clamp_phase`), and resets the
  turn's command trail.
- **retriever** — inlines a top-k snippet into `state["context"]` ahead of the
  worker, on every provider (no tools are bound any more).
- **worker → executor → worker** — a real graph cycle bounded by
  `max_command_rounds`. The worker returns a `WorkerResponse`; the executor sends
  its `command` through the engagement guard, records it (and any findings) to the
  ledger, and — only in autonomous mode — runs it and feeds the result back as a
  recent command. Non-autonomous, the command is recorded `proposed` and the loop
  stops for the operator to run it. Every step is checkpointed, so a crash
  mid-loop is resumable and `/trace` shows the command trail.
- **critic** — returns a `CriticResponse` with an `approved` boolean (no more
  string-prefix parsing).
- **respond** — the only node that writes to `messages`, so a revised turn
  leaves exactly one rendered answer in the conversation rather than one per pass.

## State channels

State ([src/skuggi/state.py](../src/skuggi/state.py)) has one message channel plus
typed scalar channels:

```python
class _MessageChannels(TypedDict):
    messages: Annotated[list[BaseMessage], add_messages]  # the conversation


class AgentState(_MessageChannels, total=False):
    phase: Phase
    plan: list[str]
    context: str
    commands: list[CommandBrief]  # the executor's trail this turn (/trace reads it)
    worker: WorkerResponse | None
    draft: str
    approved: bool
    critique: str
    revision_count: int
    max_revisions: int
    command_rounds: int
```

`messages` is what `/history` prints and what the planner and critic read as
context. The worker no longer accumulates tool traffic in a `scratch` channel;
its per-turn working memory is the typed scalars (`worker`, `commands`,
`command_rounds`), each checkpointed every superstep so the worker ⇄ executor
loop is as resumable as the old tool cycle.

## Persistence

Every node update is checkpointed by `langgraph.checkpoint.sqlite.SqliteSaver`
into `sessions.db` in the data home (`~/.local/share/skuggi` by default),
keyed by the current thread id. Killing the process
and resuming a thread with `/thread <id>` restores the full message history.
This is separate from the engagement **ledger**
([src/skuggi/ledger.py](../src/skuggi/ledger.py)): the checkpointer is
langgraph's private store, the ledger is the harness's own record. The ledger
keeps two logs, deliberately apart:

- The **engagement timeline** — an `events` spine records, in order, every
  operator prompt, agent response, command and finding, with timestamps.
  `prompt`/`response` events carry their text; `command`/`finding` events point
  (`ref_id`) at the `commands`/`findings` row with the detail. A command links
  back to the prompt that drove it (`commands.turn_event_id`), and a finding to
  its source command (`findings.command_id`), so a finding is traceable
  prompt → command → finding. Free-typed shell commands are captured here too
  (status `passthrough`). Replaying the events in order reconstructs the whole
  session ([transcript.py](../src/skuggi/transcript.py)); the `/replay` verb
  views any session (`replay list` enumerates them). The outward-facing report
  ([reports.py](../src/skuggi/reports.py)) reads only `commands`/`findings`, so
  it never leaks prompts.
- The **harness-interaction audit** — the `audit` table logs `/skuggi` control
  verbs, filtered CLI noise, and the private `/review` critique. It is kept
  *separate* from the timeline and is never part of a client-facing report.
  `verbs.py` tags each verb `engagement` (ask/run → timeline) or `control`
  (everything else → audit); the front-ends record control-verb invocations via
  `AgentCore.note_interaction`.

The `/review` verb reads a session's timeline and asks the LLM (one-shot, so it
works on every provider) for private feedback — bottlenecks, missed
opportunities, repeated or wrong commands. It is stored in the audit log, shown
to the operator, and never client-facing.

**Harness memory** is a third store ([preferences.py](../src/skuggi/preferences.py),
`preferences.db` in the data home), holding the operator's standing operational
preferences — which tool to prefer, the language for helper scripts, reply tone.
It is deliberately *global* (one file, not per-engagement, and in the data home
rather than the working directory — a preference is about the operator, not the
target, and not the directory you happened to start in). `AgentCore` renders it into every role's
prompt (`GraphDeps.preferences` → an "Operator preferences" block in
planner/worker/critic), so a rebuild of the graph is what makes an edit take
effect. It fills two ways: the manual `memory` verb, and a post-turn automatic
capture — after the stream drains, `AgentCore.maybe_capture_preferences` gates
the message on a cheap heuristic (`looks_like_directive`) and, if it passes,
asks the LLM (one-shot) to extract any durable directive, saving it and emitting
a `remembered: …` status. `settings.memory_auto` switches the automatic path off.

**The diagnostic log** ([logs.py](../src/skuggi/logs.py), `logs/skuggi.log` in the
data home) is a different thing again, and orthogonal to all of the above: the
ledger records what the operator and agent *did*; the diagnostic log records what
*failed* — swallowed exceptions, degraded config loads, provider/network errors —
so a silent failure leaves a durable trace instead of vanishing into a
backgrounded daemon's dead stderr. It is a rotating text file (5 MB × 5), written
by a root-logger handler that every entry point installs once at startup via
`setup_logging`; modules only ever `get_logger(__name__)`. There is no console
handler — a stream handler would corrupt the Rich TUI — so these records go to the
file alone. The level is `SKUGGI_LOG_LEVEL` (or `DEBUG` under `SKUGGI_DEBUG`, else
`INFO`), and noisy third-party loggers are capped at `WARNING`.

## Standalone modules

Files that can be read top-to-bottom in one sitting:

- [config.py](../src/skuggi/config.py) — every setting, in one typed
  `pydantic-settings` object. No module-level singleton by design: a singleton
  would read the config home's `config.json` at import time and make `import
  skuggi.providers` a filesystem side effect. Storage paths default under the
  two homes in [home.py](../src/skuggi/home.py); `engagements_dir` is the one
  that stays relative to the working directory.
- [registry.py](../src/skuggi/registry.py) / [probe.py](../src/skuggi/probe.py)
  / the rendering half of [doctor.py](../src/skuggi/doctor.py) — the recognized-
  tool data model, host probing + install, and the doctor tables respectively.
- [logs.py](../src/skuggi/logs.py) — the diagnostic-log setup: `setup_logging`
  (the rotating file handler every entry point installs once) and `get_logger`.
  Resolves its path under the data home at call time, never at import.
- [memory.py](../src/skuggi/memory.py) — a `SqliteSaver` wrapper and thread
  enumeration through the checkpointer's own `list` API.
- [preferences.py](../src/skuggi/preferences.py) — the harness-memory store: a
  lock-guarded SQLite table of operator preferences, plus the cheap
  `looks_like_directive` gate for automatic capture.
- [vectorstore.py](../src/skuggi/vectorstore.py) — a lazily-loaded FAISS index;
  nothing is embedded until the first `ingest`, so the REPL boots without
  embedding credentials.
- [codex_chat.py](../src/skuggi/codex_chat.py) — a `CodexTokenStore` (auth.json
  and the OAuth refresh) and a `CodexAuth` (`httpx.Auth`) under a thin
  `ChatOpenAI` subclass. See [codex-auth.md](codex-auth.md).

## The shell wrapper

The default `skuggi` command runs your real `$SHELL` as a child that inherits
the terminal, so `ls`, `cat`, `nmap` colours, completion, history and `Ctrl+C`
are handled natively by the shell — skuggi never sits in the keystroke path. It
points the child at a temporary init file that sources your own rc, prepends 🐐
to the prompt, and defines a shell **function** literally named `/skuggi` (both
bash and zsh resolve a function by that name before treating the word as a
path). The function forwards its arguments to the thin `skuggi-client`, which
talks to a warm in-process agent daemon
([src/skuggi/daemon.py](../src/skuggi/daemon.py)) over a Unix socket — so a
`/skuggi` prompt reaches a graph/ledger/engagement already loaded, with no
per-call cold start. `/skuggi exit` leaves. bash and zsh get the hook; other
shells degrade to a plain child with `/skuggi` disabled.

Enforcement scope, stated honestly: the boundary applies to commands the *agent*
proposes (the worker's `command`, guarded by the executor). Commands you free-type in the shell are your own
and are not vetoed — reliable pre-exec interception of a live interactive shell
is not feasible across shells. They are, however, *logged*: a zsh `preexec`
hook (a bash `PROMPT_COMMAND` equivalent) forwards each free-typed command to
the daemon, which records it on the timeline as `passthrough` (navigation noise
like `cd`/`ls` is filtered to the audit `cli` channel). The forwarder guards
against its own `/skuggi`/`skuggi-client` calls, runs backgrounded, and fails
open — logging never blocks or breaks your real shell.

## Dispatch and the attach protocol

Both front-ends are **verb-first**: the first word is the action, the rest is
its input. One registry ([verbs.py](../src/skuggi/verbs.py)) is the single
source of the known-verb set, argument hints and the `/help` listing, so the
REPL's `/verb` table and the daemon's socket dispatch can never drift. The
handlers live in each front-end (Rich tables and colour in the REPL, plain text
over the socket) but route off the same registry; the REPL additionally treats
bare text as an implicit `ask`.

The wire protocol is line-delimited JSON with two shapes:

- **one-shot** — the client sends `{"op":"input","text":…}`, the daemon streams
  `{"chunk":…}` frames and closes with `{"end":true,"exit":<bool>}`. This is
  every `/skuggi <verb>` invocation; `exit` true tells the client to leave the
  shell.
- **attach** — a bare `/skuggi` sends `{"op":"attach"}` and then runs an
  interactive loop over the *same* connection: each line is sent, its reply
  streamed, and the session (thread, ledger, engagement) stays live between
  lines. `Daemon.run_attached` drives it with the same dispatch as a one-shot
  input. Leaving the loop (blank line / `exit` / `Ctrl-D`) returns to the shell
  with the daemon still warm; only the one-shot `/skuggi exit` leaves the shell.

Interactive verbs prompt back through an **`{"ask":…}` frame**: the daemon emits
a question, the client prompts the operator and sends the answer as the next
`input`, and the whole exchange runs inside one attach reply. This is how the
`engagement setup` wizard ([wizard.py](../src/skuggi/wizard.py)) and the
natural-language `config` escalation ([configflow.py](../src/skuggi/configflow.py))
work; both are front-end-agnostic (the REPL supplies its `PromptSession`, the
attach loop supplies the socket round-trip) so one implementation serves both.
`AgentCore.load_engagement` hot-reloads a rewritten scope into the running
session — new workspace, ledger, tools and graph — without a restart.

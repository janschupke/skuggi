# Architecture

skuggi is a pentest harness layered on a LangChain + LangGraph agent. The
headless core ([src/skuggi/core.py](../src/skuggi/core.py), `AgentCore`) owns a
session — engagement scope, tool registry, ledger, checkpointer, the compiled
graph — and streams turn events. Two front-ends render it: the Rich +
prompt_toolkit REPL ([src/skuggi/tui.py](../src/skuggi/tui.py)) and the
wrapped-shell daemon ([src/skuggi/daemon.py](../src/skuggi/daemon.py)). Neither
holds agent logic; `AgentCore.turn` yields `TurnEvent`s (reset / status / token
/ final) so the same stream drives a Rich `Live` pane and a plain socket alike.

## The graph

```
START → planner → retriever → worker ──┬── tools ──┐
                                       │           │ (loops back to worker)
                                       └── finalize ┴─→ critic ─┬─ APPROVED → respond → END
                                                                ├─ max revs → respond → END
                                                                └─ else → bump → planner
```

- **planner** — reads the conversation, the latest request and any prior
  critique, and emits a short numbered plan. It also resets the worker's scratch
  channel for this pass.
- **retriever** — for providers that *cannot* bind tools, inlines a top-k
  snippet into `state["context"]`. A no-op when tools are available, since the
  `retrieve` tool covers that case.
- **worker → tools → worker** — a real graph cycle, bounded by
  `max_tool_rounds`. Every intermediate assistant message and tool result is
  checkpointed, so a crash mid-loop is resumable and `/trace` can show the trail.
- **critic** — replies `APPROVED: <reason>` or `REVISE: <issue>`; anything that
  is not an approval is treated as a revision request.
- **respond** — the only node that writes to `messages`, so a revised turn
  leaves exactly one answer in the conversation rather than one per pass.

## State channels

State ([src/skuggi/state.py](../src/skuggi/state.py)) has two message channels,
deliberately separate:

```python
class _MessageChannels(TypedDict):
    messages: Annotated[list[BaseMessage], add_messages]  # the conversation
    scratch: Annotated[list[BaseMessage], add_messages]  # the worker's tool loop


class AgentState(_MessageChannels, total=False):
    plan: str
    context: str
    draft: str
    critique: str
    revision_count: int
    max_revisions: int
    tool_rounds: int
```

`messages` is what `/history` prints and what the planner and critic read as
context. `scratch` holds the worker's own prompt scaffolding and tool traffic —
kept apart because a seeded `HumanMessage` is otherwise indistinguishable from a
real user turn.

## Persistence

Every node update is checkpointed by `langgraph.checkpoint.sqlite.SqliteSaver`
into `./data/sessions.db`, keyed by the current thread id. Killing the process
and resuming a thread with `/thread <id>` restores the full message history.
This is separate from the engagement **ledger**
([src/skuggi/ledger.py](../src/skuggi/ledger.py)): the checkpointer is
langgraph's private store, the ledger is the harness's own record of commands
and findings.

## Standalone modules

Files that can be read top-to-bottom in one sitting:

- [config.py](../src/skuggi/config.py) — every setting, in one typed
  `pydantic-settings` object. No module-level singleton by design: a singleton
  would read `configs/config.json` at import time and make `import
  skuggi.providers` a filesystem side effect.
- [registry.py](../src/skuggi/registry.py) / [probe.py](../src/skuggi/probe.py)
  / the rendering half of [doctor.py](../src/skuggi/doctor.py) — the recognized-
  tool data model, host probing + install, and the doctor tables respectively.
- [memory.py](../src/skuggi/memory.py) — a `SqliteSaver` wrapper and thread
  enumeration through the checkpointer's own `list` API.
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
proposes through `run_command`. Commands you free-type in the shell are your own
and are not vetoed — reliable pre-exec interception of a live interactive shell
is not feasible across shells.

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

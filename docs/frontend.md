# The front-ends: the shell wrapper, dispatch, and the attach protocol

skuggi's headless `AgentCore` ([src/skuggi/agent/core.py](../src/skuggi/agent/core.py))
owns the session and streams `TurnEvent`s; it holds no rendering. Three front-end
surfaces render it, all reading one verb registry so they can never drift:

- the **wrapped shell** (`skuggi`) — your real `$SHELL`, with `/skuggi <verb>`
  reaching a warm daemon;
- the **chat loop** — a bare `/skuggi`, an interactive loop over the same daemon;
- the **standalone REPL** (`skuggi-repl`) — a pure Rich + prompt_toolkit agent chat.

The dispatch grammar is documented in [usage.md](usage.md); the mechanics are here.

## The shell wrapper

The default `skuggi` command runs your real `$SHELL` as a child that inherits the
terminal, so `ls`, `cat`, `nmap` colours, completion, history and `Ctrl+C` are
handled natively by the shell — skuggi never sits in the keystroke path. It points
the child at a temporary init file that sources your own rc, prepends 🐐 to the
prompt, and defines a shell **function** literally named `/skuggi` (both bash and
zsh resolve a function by that name before treating the word as a path). The
function forwards its arguments to the thin `skuggi-client`, which talks to a warm
in-process agent daemon ([src/skuggi/frontend/daemon.py](../src/skuggi/frontend/daemon.py))
over a Unix socket — so a `/skuggi` prompt reaches a graph/ledger/engagement already
loaded, with no per-call cold start. `/skuggi exit` leaves. bash and zsh get the
hook; other shells degrade to a plain child with `/skuggi` disabled.

Enforcement scope, stated honestly: the boundary applies to commands the *agent*
proposes (the worker's `command`, guarded by the executor). Commands you free-type
in the shell are your own and are not vetoed — reliable pre-exec interception of a
live interactive shell is not feasible across shells. They are, however, *logged*: a
zsh `preexec` hook (a bash `PROMPT_COMMAND` equivalent) forwards each free-typed
command to the daemon, which records it on the timeline as `passthrough` (navigation
noise like `cd`/`ls` is filtered to the audit `cli` channel). The forwarder guards
against its own `/skuggi`/`skuggi-client` calls, runs backgrounded, and fails open —
logging never blocks or breaks your real shell.

## Dispatch and the attach protocol

All front-ends are **verb-first**: the first word is the action, the rest is its
input. One registry ([verbs.py](../src/skuggi/frontend/verbs.py)) is the single
source of the known-verb set, the noun set for the grouping verbs, argument hints
and the `help` listing, so the REPL's command table and the daemon's socket dispatch
can never drift (a drift test pins each front-end's router against `verbs.KNOWN` and
`verbs.noun_names`). The handlers live in each front-end (Rich tables and colour in
the REPL, plain text over the socket) but route off the same registry; the REPL
additionally treats bare text as an implicit `ask`.

The wire protocol is line-delimited JSON with two shapes:

- **one-shot** — the client sends `{"op":"input","text":…}`, the daemon streams
  `{"chunk":…}` frames and closes with `{"end":true,"exit":<bool>}`. This is every
  `/skuggi <verb>` invocation; `exit` true tells the client to leave the shell.
- **attach** — a bare `/skuggi` sends `{"op":"attach"}` and then runs an interactive
  loop over the *same* connection: each line is sent, its reply streamed, and the
  session (thread, ledger, engagement) stays live between lines. Leaving the loop
  (blank line / `exit` / `Ctrl-D`) returns to the shell with the daemon still warm;
  only the one-shot `/skuggi exit` leaves the shell.

Interactive verbs prompt back through an **`{"ask":…}` frame** (and `{"choose":…}` /
`{"confirm":…}` for pick-lists and yes/no): the daemon emits a question, the client
prompts the operator and sends the answer as the next `input`, and the whole
exchange runs inside one attach reply. This is how the `engagement setup` wizard
([wizard.py](../src/skuggi/frontend/wizard.py)), the guided provider/credential setup
([setup.py](../src/skuggi/frontend/setup.py)), and the natural-language `set config`
escalation ([configflow.py](../src/skuggi/frontend/configflow.py)) work; all are
front-end-agnostic (the REPL supplies its `PromptSession`, the attach loop the socket
round-trip) so one implementation serves both. `AgentCore.adopt_engagement`
hot-reloads a rewritten scope into the running session — new workspace, ledger, tools
and graph — without a restart.

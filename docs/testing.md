# Testing

Five layers. The first three are offline and are what `make check` runs; the
last two talk to the real world (a provider, the docker lab) and are opt-in.

```
make check     # format --check, ruff, mypy, pytest (L1-L3)   -- what CI runs
make eval      # L4 only: real providers, costs money
make e2e       # L5 only: the real pipeline against the docker lab
```

| Layer | Directory | What is real | What is faked |
|---|---|---|---|
| L1 unit | `tests/unit` | pure functions | everything else |
| L2 integration | `tests/integration` | ToolNode, reducers, SqliteSaver, FAISS, the openai SDK | the LLM, the socket |
| L3 harness | `tests/harness` | the REPL and console scripts | the LLM, the terminal |
| L4 eval | `tests/eval` | **the provider** | nothing |
| L5 e2e | `tests/e2e` | **the whole execution pipeline against the docker lab** | the LLM (scripted worker) |

## Why the split

**L1** covers logic with a right answer: the arithmetic whitelist and its caps,
the path-escape guard, JWT parsing, history windowing, the critic's router,
settings resolution.

**L2** wires real components together with a fake socket. The graph runs over a
real checkpointer and the real engagement guard + ledger; FAISS indexes real
vectors from deterministic fake embeddings; the codex client is a real
`ChatOpenAI` on a real openai SDK over `respx`, so those assertions pin the bytes
the endpoint receives. This layer owns the regression tests for the structured
worker/executor cycle, the 401 refresh, the bounded command loop and the revision
cutoff.

**L3** drives the app through its real entry points with an injected console, so
rendered output is assertable without a terminal.

**L4** is the only layer that can tell you the agent actually *works*. It
asserts behavioural properties -- did the worker reach for the calculator, did
retrieval supply a fact that exists only in an ingested document, did turn two
resolve a reference from turn one -- and never exact strings, because a real
model is nondeterministic.

**L5** is the only layer that runs a *real command against a real target*. Every
other layer that exercises the executor monkeypatches `skuggi.execution.run`; L5
lets it run for real (`shell=False`, argv exec'd) against the dockerized lab
([docs/lab.md](lab.md)) and asserts on the captured output. The worker is
*scripted* — it proposes a real `curl`/`nmap` command, so the test is
deterministic and free — but everything below the LLM is the production path a
real engagement uses: the engagement guard, the tool registry, the ledger, the
subprocess, and `/report`. It reuses the app's own wiring (`AgentCore` via
`tests.support.engaged_core`) rather than re-assembling a graph, so it can't
drift from what the REPL/daemon do. It skips cleanly when the lab is down.

## Rules that keep this honest

**Automated tests never touch a provider or spawn a process.** Three autouse
fixtures enforce it: `no_network` makes a forgotten mock raise instead of
reaching the internet, `no_subprocess` does the same for command execution, and
`isolate_credentials` strips the provider env vars, redirects the `auth.json`
lookup, and chdirs to a temp directory so `Settings` cannot read the repo's own
`configs/config.json`. `test_suite_does_not_see_real_credentials` guards the fixture itself --
if isolation breaks, every credential assertion elsewhere becomes meaningless.
The two live layers (L4 eval, L5 e2e) are exempt via `_is_live`: eval needs a
provider, e2e needs the network and subprocess blocks lifted to reach the lab
and run real tools.

**`filterwarnings = ["error"]`.** Two ignores, both explained where they are
declared. The live layers additionally exempt `ResourceWarning`, because real
SDKs (and httpx's pooled connections) keep TLS sockets past the end of a test;
every offline layer keeps the strict setting.

**Coverage gate at 90%** (`[tool.coverage.report] fail_under`), measured with
branch coverage. It lives in config rather than in `addopts` so a standalone
`coverage report` agrees with pytest. The live layers run a tiny slice of the
code, so `make eval` and `make e2e` pass `--no-cov` — without it a fully passing
live run would still exit non-zero on the 90% floor.

## Two traps worth knowing

Fake embeddings derive their vectors from **character counts, not `hash()`**.
`hash()` is salted per process, so a hash-derived fake produces a FAISS index
that is not reproducible across runs, and the persist/reload test would pass or
fail depending on the interpreter's mood.

The scripted chat model gives **every reply a fresh message id**. `add_messages`
treats a repeated id as a replacement rather than an append, so returning the
same scripted `AIMessage` object twice silently overwrites the previous entry --
which quietly breaks any multi-round tool cycle under test.

## Running the eval layer

Needs credentials. Each provider skips with a reason when it is unavailable, so
a partial run is normal:

```
$ make eval
8 passed, 2 skipped
SKIPPED  ANTHROPIC_API_KEY is not set
SKIPPED  no Ollama server at http://localhost:11434
```

A provider you have no credentials for skips rather than fails, so a partial
run is the normal outcome.

If a chatgpt case skips with `400 - The '<model>' model is not supported when
using Codex with a ChatGPT account`, that is a stale model name, not an
account problem -- see docs/codex-auth.md. The skip is
matched narrowly on that phrase so every other provider error still fails.

## Running the e2e layer

Needs the docker lab up ([docs/lab.md](lab.md)); when it is down the whole layer
skips with a fix hint rather than failing:

```
$ make e2e
7 passed, 1 skipped
SKIPPED  192.0.2.10 is not directly routable      # macOS without WireGuard

# with the lab down:
$ make e2e
8 skipped
SKIPPED  skuggi lab is not reachable at http://127.0.0.1:8080 -- bring it up: ...
```

Bring it up first (`cd lab && docker compose up -d --wait`), or set
`SKUGGI_E2E_COMPOSE_UP=1` to have the fixture start it and tear it down (`down
-v`) at the end. The port is discovered from `docker compose port web 80`, so a
collision remap is handled automatically. The loopback cases run everywhere; the
direct-`192.0.2.10` cases run only when that IP is routable and skip otherwise.
Each case also skips when its tool (`curl`/`nmap`/…) is not installed on the
host.

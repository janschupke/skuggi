# Testing

Four layers. The first three are offline and are what `make check` runs; the
fourth talks to real providers and is opt-in.

```
make check     # format --check, ruff, mypy, pytest (L1-L3)   -- what CI runs
make eval      # L4 only: real providers, costs money
```

| Layer | Directory | What is real | What is faked |
|---|---|---|---|
| L1 unit | `tests/unit` | pure functions | everything else |
| L2 integration | `tests/integration` | ToolNode, reducers, SqliteSaver, FAISS, the openai SDK | the LLM, the socket |
| L3 harness | `tests/harness` | the REPL and console scripts | the LLM, the terminal |
| L4 eval | `tests/eval` | **the provider** | nothing |

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

## Rules that keep this honest

**Automated tests never touch a provider.** Two autouse fixtures enforce it:
`no_network` makes a forgotten mock raise instead of reaching the internet, and
`isolate_credentials` strips the provider env vars, redirects the `auth.json`
lookup, and chdirs to a temp directory so `Settings` cannot read the repo's own
`configs/config.json`. `test_suite_does_not_see_real_credentials` guards the fixture itself --
if isolation breaks, every credential assertion elsewhere becomes meaningless.

**`filterwarnings = ["error"]`.** Two ignores, both explained where they are
declared. The eval layer additionally exempts `ResourceWarning`, because real
provider SDKs keep pooled TLS connections past the end of a test; every offline
layer keeps the strict setting.

**Coverage gate at 90%** (`[tool.coverage.report] fail_under`), measured with
branch coverage. It lives in config rather than in `addopts` so a standalone
`coverage report` agrees with pytest.

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

# The structured protocol

**Every LLM interaction is a strict structured exchange** — never free text
pasted to or from a model. Defined in `agent/protocol.py`; prose in
[docs/architecture.md](../../docs/architecture.md#the-structured-protocol).

- The harness builds a `RequestContext` (history, scope + stance, phase, prior
  findings, commands run this turn) and `render_request` turns it into one
  labelled block.
- Each node returns a validated pydantic response (`PlannerResponse`,
  `WorkerResponse`, `CriticResponse`) through the single `structured_invoke`
  seam: native `with_structured_output` where the provider supports it, a JSON
  contract + one repair retry on the tool-less chatgpt path.
- `render_response` lays the response out deterministically, so the operator
  only ever sees model text inside fields the harness placed.

## Rules

- **All prompt text lives in `agent/prompts.py`.** Don't inline a prompt string
  at a call site. `agent/modes.py` is a thin compatibility shim over it.
- **Add a field to the pydantic response, not a new free-text channel.** If a
  node needs to return something, it returns it as typed data the renderer
  places — the no-raw-model-output guarantee depends on it.
- **A new structured call goes through `structured_invoke`**, so the chatgpt
  JSON-fallback path keeps working; don't call `with_structured_output` directly.

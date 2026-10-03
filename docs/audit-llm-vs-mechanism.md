# Audit: LLM reasoning where a deterministic mechanism exists

The guiding rule for this harness is **the model proposes within a constrained,
validated vocabulary; deterministic code owns computation and enforcement.** This
audit lists every place a prompt asked the LLM to decide something a standard or a
mechanism already answers, and what was done about it.

## Findings

| Site | Before | Mechanism | Resolution |
|---|---|---|---|
| Finding **severity** (`FindingDraft.severity`) | A free pick from a 5-value enum with no rubric (the only guidance was "record anything noteworthy"). | **CVSS v3.1** — a published formula. | The worker now supplies a CVSS **vector**; `skuggi.frameworks.cvss` computes base/temporal/environmental deterministically and the band is derived. The model never computes a score. |
| Finding **classification** | None — findings carried no taxonomy at all. | **OWASP WSTG** (web) and **MITRE ATT&CK** (TTPs) id schemes. | Findings carry validated `refs` from the engagement's enabled taxonomies, resolved to id + title + link. Applied *where they fit* — never forced (see ATT&CK note). |
| Per-engagement **threat model** | Not represented; severity was engagement-blind. | **CVSS Environmental** metric group. | An optional `threat_model` (CR/IR/AR) on the scope is folded into the vector, so scores reflect the asset context — still deterministic. |

## Already correct (kept as the templates to emulate)

- **Phase advancement** — `protocol.clamp_phase` decides; the planner only *suggests*
  `advance_to`. Code owns the state machine.
- **Command method** — the tool registry declares a static method per binary; the
  guard reads it. Not an LLM decision.
- **Scope / authorization** — `engagement.check_command` is a deterministic guard; the
  critic's scope clause is defence-in-depth only, never the enforcement.

## Deliberately left to the LLM (no mechanism exists)

- The CVSS **vector metrics** themselves (AV:N vs AV:L, etc.) — assessing a
  vulnerability is judgement. It is captured verbatim in the stored vector and the
  operator can override it, so the *input* is auditable even though it is not
  mechanical. The arithmetic over it is not.
- Whether a finding is noteworthy, prose summaries/conclusions, the private session
  review, and durable-preference extraction — all genuine judgement.

## Why ATT&CK is never forced

ATT&CK is a **descriptive knowledge base of adversary techniques**, not a
prescriptive methodology. A web-vuln finding maps cleanly to a WSTG id and a CVSS
vector; forcing a technique id onto it would be a fabricated mapping — the exact
anti-pattern this audit removes. ATT&CK is therefore an *optional* classifier
(strong default in red-team engagements) and may additionally drive an
adversary-emulation engagement, but a finding gets a technique id only when one
genuinely applies.

## Follow-on audit: finding lifecycle, score staleness, report versioning

A second pass hardened the finding/report data model:

- **No review state → draft/approved/rejected + author.** Findings were recorded and
  reported immediately. Now every finding (agent or operator) is born `draft`, the
  operator approves/rejects (with a reason), and **only approved findings reach a
  report**. The LLM critic still approves the *turn*, not findings — review is the
  operator's. A rejection reason is fed back to the agent so it stops re-asserting it.
- **Threat model baked into the score → versioned + rescorable.** The engagement
  threat model was merged into each finding's stored vector, so a later change could
  not be reflected. Now the stored vector is the worker's **intrinsic** one; the
  threat model is overlaid only to derive the environmental score and tagged with a
  **version**. A change is logged (`threat_model_versions`), affected findings are
  flagged outdated, and `findings rescore` recomputes them — recorded scores are
  immutable except on that explicit action.
- **Reports: timestamped but no revision trail → diff + changelog.** Reports were
  already timestamped and non-overwriting; each is now numbered, cites the previous
  revision, and emits a unified `.diff` (the revision notes), with an optional manual
  `report note` changelog.

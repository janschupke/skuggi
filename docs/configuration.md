# Configuration and storage

skuggi is a command you run from anywhere, so its files do not live next to your
cwd. It follows the **XDG Base Directory** convention — the same config/data split
most modern CLI tools use, seeded by `skuggi-init`. Editable config (small,
backup-friendly) lives under the **config home**; regenerable state (databases, the
FAISS index, logs) lives under the **data home**. The one deliberate exception is
the engagement root, which stays relative to your working directory (see
[engagement.md](engagement.md)).

| | Default | Overrides | Holds |
|---|---|---|---|
| **Config home** | `~/.config/skuggi` | `SKUGGI_CONFIG_HOME`, else `XDG_CONFIG_HOME/skuggi` | `config.json`, `tools.json`, `layout.json`, `commands.json`, `env` |
| **Data home** | `~/.local/share/skuggi` | `SKUGGI_DATA_HOME`, else `XDG_DATA_HOME/skuggi` | `sessions.db`, `preferences.db`, `faiss_index/`, `toolbox/`, `logs/` |

`skuggi-doctor` prints where every one of these resolved on this machine — start
there rather than reasoning about the defaults.

## Storage layout

Harness config, in the **config home** (`~/.config/skuggi`):

- `config.json` — app config (the `set config` verb edits this)
- `tools.json` — the recognized-tool registry
- `layout.json`, `commands.json` — optional workspace layout and `cmd` cheatsheet
- `env` — optional secrets file (`chmod 600`)
- `scope.example.json` — the template to copy for a new engagement

Harness state, in the **data home** (`~/.local/share/skuggi`):

- `sessions.db` — LangGraph checkpoint store
- `preferences.db` — harness memory (global operator preferences)
- `faiss_index/` — FAISS retrieval index
- `toolbox/` — the managed tool venv (`tool_source = managed|combine`)
- `logs/skuggi.log` — the diagnostic log (rotating; `SKUGGI_LOG_LEVEL`)
- `ledger.db`, `reports/` — agent-only fallback when no engagement is selected

Per-case, **relative to your working directory**: `<engagement root>/` — the
directory you adopt with `set engagement` (its scope, ledger, recon output and
reports; keep it out of git). The templates themselves ship inside the package
([src/skuggi/templates/](../src/skuggi/templates/)) so an install with no checkout
can still seed a config home.

## Resolution precedence

Values resolve in priority order, highest first:

1. an environment variable (prefix `SKUGGI_*`, or the unprefixed vendor names)
2. `<config home>/env` — same spelling as the environment, so
   `SKUGGI_PROVIDER=anthropic` and a bare `ANTHROPIC_API_KEY=...`
3. `<config home>/config.json`
4. the built-in defaults

So a one-off `SKUGGI_PROVIDER=anthropic` still wins for a single run. A path you
set explicitly is taken as written, so a *relative* one still resolves against the
working directory — `SKUGGI_CONFIG_PATH=./configs/config.json` gives you a
project-local config if you want one.

## Config tiers

- **App config** (`<config home>/config.json`): providers/models, embedding models,
  storage paths, graph bounds, mode, execution backend, OSINT/research tuning.
  Edit it directly or with the `set config` verb.
- **Harness config** (shared, same home): the recognized-tool registry `tools.json`,
  the optional workspace-layout override `layout.json`, and the optional `cmd`
  cheatsheet `commands.json`.
- **Engagement setup** (per-case, in `<engagement root>/scope.json`): the boundary —
  see [engagement.md](engagement.md).

### The `config` verb

`show config` prints every setting with credentials redacted. `set config <key>
<value>` validates and persists one setting, applying `provider`/`mode` to the live
session (other keys take effect on restart). `set config <natural-language request>`
asks the LLM to propose `key=value` edits, shows them, and applies them on your
confirmation. It never writes a secret.

## The config-key surface

The typed settings model is
[src/skuggi/config/config.py](../src/skuggi/config/config.py) (`Settings`,
`env_prefix="SKUGGI_"`). The main keys:

- **Providers / models** — `provider`, `model_openai`, `model_chatgpt`,
  `model_anthropic`, `model_claude_cli`, `model_ollama`, `reasoning_effort`,
  `review_model` (the `review` critique; `None` = the active model).
- **Embeddings / retrieval** — `embedding_model`, `embedding_model_ollama`,
  `chunk_size`, `chunk_overlap`, `retrieve_k`, `retrieve_on_recon`.
- **Graph bounds** — `max_revisions`, `max_tool_rounds`, `history_messages`,
  `history_chars`, `compact_history`, `findings_limit`, `commands_limit`, `mode`.
- **Storage paths** — `sqlite_path`, `faiss_path`, `preferences_path`, `log_path`,
  `log_level`, `registry_path`, `layout_path`, `commands_path`, `engagement_root`
  (the one cwd-relative path), `managed_tools_dir`.
- **Tools / execution** — `tool_source` (`host|managed|combine`),
  `command_timeout_s`, `passthrough_skip` (free-typed commands logged as CLI noise,
  not the timeline), `wordlist_roots` (system wordlist dirs a tool may read from).
- **Harness memory** — `memory_auto` (propose standing directives post-turn),
  `memory_max` (cap, default 100).
- **Codex / OpenAI** — `codex_auth_path` (`~/.codex/auth.json`),
  `codex_responses_base`, `codex_refresh_url`, `codex_authorize_url`,
  `ollama_base_url`.
- **OSINT / research / forensics** — see
  [osint-research.md](osint-research.md#configuration) and
  [engagement.md](engagement.md#forensics-mode).

### Execution backend

How an agent-cleared command is run:

| Key | Default | Meaning |
|---|---|---|
| `execution_backend` | `host` | `host` (hardened subprocess) or `container` (throwaway docker/podman) |
| `container_image` | `kalilinux/kali-rolling` | the image a container run uses |
| `container_runtime` | `docker` | `docker` or `podman` |
| `container_network` | `none` | container network; set an egress-filtered network name when the engagement needs egress |

The container backend gives OS-level isolation (read-only rootfs, caps dropped,
resource caps, only the workspace writable); its network defaults to `none`.

## Secrets never go in `config.json`

API keys and tokens are **env-only** — `OPENAI_API_KEY`, `ANTHROPIC_API_KEY`,
`SHODAN_API_KEY`, `APIFY_TOKEN`, `OSINT_SEARCH_API_KEY`, `NVD_API_KEY` (plus
`OLLAMA_BASE_URL`). They are read from the environment, from `<config home>/env`, or
(for OpenAI/ChatGPT) from `~/.codex/auth.json`; see [.env.example](../.env.example)
for the `env` template. The JSON config source **drops** these fields even if a file
mistakenly contains one; the `env` file is *not* filtered, because holding
credentials is the only reason it exists. Keep it at `chmod 600` — `skuggi-doctor`
warns if it is group- or world-readable. For installing and seeding these homes, see
[install.md](install.md).

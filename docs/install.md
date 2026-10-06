# Installing the `skuggi` command

skuggi is meant to be typed from wherever you are working — in a client
directory, in `~`, on a jump host — not from its own checkout. This document is
the long form of the README's Install section: what the install actually does,
where everything ends up, and what to check when it misbehaves.

## The one command

Clone the repo somewhere **permanent** first — the install is editable, so this
checkout is referenced for the life of the install (see the `--editable` note
below). Do not clone to a temp dir, and do not move or delete it afterward; if
you must relocate it, re-run `make install-cli` from the new path.

```sh
git clone <repo-url> ~/dev/skuggi
cd ~/dev/skuggi
make install-cli
```

Three steps, and each is worth knowing about:

```sh
uv tool install --editable '.[pdf]' --force    # 1
uv tool update-shell                           # 2
uv run skuggi-init                             # 3
```

**1. `uv tool install --editable '.[pdf]' --force`** builds skuggi into its own
isolated environment under `uv tool dir` and drops every `[project.scripts]`
entry point into `uv tool dir --bin` (usually `~/.local/bin`): `skuggi`,
`skuggi-repl`, `skuggi-init`, `skuggi-ingest`, `skuggi-doctor`, `skuggi-client`,
`skuggi-login`, `skuggi-pdf`, `skuggi-visualize`, `skuggi-eval`.

- `--editable` matters for two reasons beyond convenience. The tool
  environment's `.pth` points back at this checkout's `src`, so a code edit is
  live without reinstalling — and `Path(__file__)` still resolves inside the
  repo, which is how the `update` verb finds a git repository to pull.
- `'.[pdf]'` is an **extra**, not a dependency group. `uv tool install` has no
  `--group` flag of any kind, so a PEP-735 group can only ever populate a dev
  checkout; shipping the report pipeline as an extra is what keeps `skuggi-pdf`
  and `/report pdf` working for a globally installed skuggi. (WeasyPrint still
  needs a system Pango: `brew install pango`, or
  `apt install libpango-1.0-0 libpangoft2-1.0-0`.)
- `--force` makes the command a safe re-run. Without it, uv refuses when an
  entry-point name already exists in the bin directory.
- A tool environment is **not** locked against `uv.lock`. `uv tool install` has
  no `--frozen`/`--locked`, so it resolves fresh from PyPI and can differ from
  what `./.venv` and CI pin. The version caps in `pyproject.toml` are the only
  thing holding it in line.

**2. `uv tool update-shell`** appends the bin directory to your shell profile if
it is not already on `$PATH`. It is a no-op when it is.

**3. `skuggi-init`** creates the two homes and fills them (see below).

Then **open a new shell** — the `$PATH` change does not reach the one you ran
`make install-cli` in — and check:

```sh
command -v skuggi
skuggi-doctor        # the install table is the first thing it prints
```

## Where everything lives

skuggi follows the **XDG Base Directory** convention: editable config you might
keep in dotfiles lives in one home, regenerable state (databases, the FAISS
index, history) you would never back up lives in another. That is the whole
reason for the split — not a bespoke scheme. Plus one deliberate exception.

| | Default | Overrides |
|---|---|---|
| Config home | `~/.config/skuggi` | `SKUGGI_CONFIG_HOME`, else `XDG_CONFIG_HOME/skuggi` |
| Data home | `~/.local/share/skuggi` | `SKUGGI_DATA_HOME`, else `XDG_DATA_HOME/skuggi` |

```
~/.config/skuggi/
  config.json           # app config; the `config` verb edits this
  tools.json            # the recognized-tool registry
  layout.json           # optional workspace-layout override
  commands.json         # optional `cmd` cheatsheet
  env                   # optional secrets file (chmod 600)
  scope.example.json    # template to copy for a new engagement

~/.local/share/skuggi/
  sessions.db  preferences.db  faiss_index/  toolbox/
  ledger.db  reports/          # agent-only fallback, no engagement selected
  logs/skuggi.log              # diagnostic log (rotating); SKUGGI_LOG_LEVEL

<engagement root>/     # a directory you adopt; RELATIVE to your working directory
```

The engagement root is the exception, and the reason the split exists: an
engagement's scope, ledger, recon output and reports belong to the directory you
adopted (the current one, or `set engagement <path>`), not to a global dotdir.
Harness config describes
*you*; a workspace describes *a case*. Everything else is global so that
`skuggi` in `~` and `skuggi` in `~/work/acme` are the same harness with the same
memory and the same session history.

`skuggi-doctor` prints where each of these resolved on this machine — start
there rather than reasoning about the table above. For the full file reference,
the resolution precedence and the complete config-key surface, see
[configuration.md](configuration.md).

### Overriding a path

Anything you set explicitly is used as written, so a *relative* override still
resolves against the working directory. That is how you get a project-local
config if you want one:

```sh
cd ~/dev/skuggi
SKUGGI_CONFIG_PATH=./configs/config.json uv run skuggi
```

## `skuggi-init`: seeding and the one-time migration

`skuggi-init` does two things, in this order, and never overwrites or deletes
anything:

1. **Migrates**, when the install resolves to a checkout. Any live
   `configs/*.json` and `data/*` there is *moved* into the homes. That state is
   gitignored — a session history, a ledger, the harness memory, past reports —
   so it exists nowhere else, and leaving it behind would silently orphan it the
   moment the defaults changed. It moves rather than copies so there is exactly
   one live copy of each database. This does not depend on your working
   directory: an editable install resolves back into the checkout from anywhere,
   so the migration happens on the first run wherever you launch it.
2. **Seeds** whatever is still missing, from the templates shipped inside the
   package at `src/skuggi/templates/`. They live inside the package rather than
   at `./configs` precisely so an install with no checkout can still seed a
   config home.

Both halves are guarded on the destination not existing, so re-running is safe
and a second checkout can never clobber the first one's data.

## Credentials

The app owns its credentials. Start `skuggi` (it boots with or without a
configured provider) and run `set provider` with no name: it walks you through
choosing a provider and, for `openai`/`anthropic`, writes the key to
`~/.config/skuggi/env` at mode 0600 for you — no `export`, no editing files by
hand. For a ChatGPT account, `set provider` → `chatgpt` (or `login`, or
`skuggi-login` before you start) runs the OAuth browser flow itself and writes
`~/.codex/auth.json`. `ollama` needs no credential. `skuggi-doctor` shows which
providers are configured.

Setting them by hand still works if you prefer:

```sh
printf 'ANTHROPIC_API_KEY=sk-ant-...\n' > ~/.config/skuggi/env
chmod 600 ~/.config/skuggi/env
```

Precedence is shell environment > `<config home>/env` > `config.json` >
defaults. Keys in `config.json` are **dropped** even if present; keys in `env`
are honoured, because holding credentials is that file's only job. See
[.env.example](../.env.example) for the template, and note the repo's own `.env`
is not loaded at all.

## How `/skuggi` finds its client

Inside the wrapped shell, `/skuggi` is a shell *function* that shells out to
`skuggi-client`. It is spelled as an **absolute path**, resolved once before the
child shell starts ([src/skuggi/frontend/shell.py](../src/skuggi/frontend/shell.py)).

It cannot rely on `$PATH`. The generated init file sources your own `~/.zshrc`
first, by design, and an rc that rebuilds `PATH` — `path=(...)` is idiomatic in
zsh — would leave `/skuggi` reporting "command not found" from inside a wrapped
shell, which is about the least debuggable place it could fail. Resolving once
also pins the hook to the same install the daemon is running from, which matters
when a checkout's `.venv` and a `uv tool` install both exist.

## `update` under each install shape

The `update` verb runs `git pull --ff-only` and then refreshes dependencies. The
second command depends on how skuggi is running, because the two install shapes
have different environments:

| Running from | Second step | Why |
|---|---|---|
| a `uv tool` environment | `uv tool install --editable <root>[pdf] --force` | `uv sync` would sync the checkout's `.venv`, not the environment skuggi is actually running in |
| the checkout's `.venv` | `uv sync --all-groups --all-extras` | that *is* the environment |
| a non-editable install | nothing — it declines | there is no checkout to pull; running git in `site-packages` is worse than doing nothing |

The tool-environment case is detected by a `uv-receipt.toml` beside
`pyvenv.cfg`, which uv writes only for a tool env. The checkout is verified (a
`pyproject.toml` and a `.git` at the expected root) rather than assumed from
`__file__` arithmetic.

Pulled *code* takes effect on restart either way, via the editable `.pth`. A new
*dependency* is what needs the right second step.

## Troubleshooting

**`skuggi: command not found`** — the bin directory is not on `$PATH`, or you
have not opened a new shell since installing. `uv tool dir --bin` prints the
directory; add it and reopen:

```sh
export PATH="$HOME/.local/bin:$PATH"
```

**`/skuggi` does nothing, or the prompt has no 🐐** — the hook is only injected
for bash and zsh. Any other `$SHELL` gets a plain child shell and a printed
note. Check `echo $SHELL`.

**`cannot read tool registry config at .../tools.json`** — the config home was
never seeded. Run `skuggi-init`. `skuggi-doctor` prints the install table even
when the probe fails, for exactly this case.

**skuggi behaves as though it were unconfigured** — you are probably looking at
a different home than you think, most often because `XDG_CONFIG_HOME` or
`SKUGGI_CONFIG_HOME` is set in one shell and not another. `skuggi-doctor` prints
the resolved paths; trust it over the defaults.

**A report renders without styling, or `/report pdf` fails** — the `pdf` extra
or its system Pango is missing. Reinstall with
`uv tool install --editable '.[pdf]' --force` and install Pango
(`brew install pango`).

**The `config` verb's changes do not take effect** — `provider` and `mode` apply
to the live session; every other key takes effect on restart.

**An engagement workspace appeared somewhere unexpected** — with no
`set engagement <path>` and no `SKUGGI_ENGAGEMENT_ROOT`, the engagement root is
the current directory, so it follows your `cd` (and `set engagement` with no path
scaffolds a `scope.json` there). That is deliberate; `skuggi-doctor` prints the
resolved `engagement root` and whether a scope was found.

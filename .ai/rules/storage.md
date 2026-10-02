# Storage & the three homes

skuggi splits its state three ways, and the split is load-bearing. Full
rationale: [docs/install.md](../../docs/install.md).

- **config home** `~/.config/skuggi` (`SKUGGI_CONFIG_HOME` > `XDG_CONFIG_HOME`)
  — `config.json`, `tools.json`, `layout.json`, `commands.json`, `env`.
- **data home** `~/.local/share/skuggi` (`SKUGGI_DATA_HOME` > `XDG_DATA_HOME`)
  — `sessions.db`, `preferences.db`, `faiss_index/`, `logs/`, toolbox.
- **`./engagements/<name>/`** stays **relative to the working directory** — an
  engagement's scope, ledger, recon and reports belong to the client dir, not
  the operator's home.

## Rules

- **Never resolve a storage path at import time.** Defaults live in
  `common/home.py`; a module-level `Path(...).expanduser()` defeats the per-test
  home redirect and is the exact anti-pattern this split exists to kill. Resolve
  at call time. Resolution order: init args > env > `<config home>/env` >
  `config.json` > defaults.
- **`config.py` has no module-level `Settings` singleton** — a singleton would
  read `config.json` at import and make `import skuggi...` a filesystem side
  effect.
- **`skuggi-init` MOVES databases** (migrates a checkout's `configs/`+`data/`
  into the homes). A smoke run that takes the default migration can walk real
  session history out of the repo — pass explicit homes.
- **Trust `skuggi-doctor`** for the resolved paths, not the defaults.
- Tests must set `SKUGGI_CONFIG_HOME`/`SKUGGI_DATA_HOME` to a tmp dir; **a green
  `make check` is not proof** — `ls ~/.config/skuggi ~/.local/share/skuggi` after
  a run, unchanged, is. See [testing.md](testing.md).

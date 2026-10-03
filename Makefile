UV ?= uv

.PHONY: install install-cli lint format typecheck test eval e2e eval-det bench bench-fast check clean pdf frameworks \
	lab-list lab-up lab-down lab-restore lab-wipe lab-verify

# The user-facing practice range controller (labs/). Standalone dev tooling --
# deliberately NOT a skuggi console script, so it never ships in the wheel.
LABCTL = $(UV) run python labs/labctl
LAB ?=

## sync the locked environment and install the git hooks
install:
	$(UV) sync --all-groups --all-extras
	$(UV) run pre-commit install
	$(UV) run pre-commit install --hook-type pre-push

## put the `skuggi` keyword on $$PATH, then seed the config and data homes.
## --editable: the tool env's .pth points back at this checkout, so code edits are
## live and the `update` verb can still find a git repo to pull.
## '.[pdf]': `uv tool install` has no --group flag, so the report pipeline has to
## travel as an extra or a global install cannot render a PDF.
## --force makes this a safe re-run (it also overwrites the bin/ entry points).
## Re-run it after changing a DEPENDENCY: `uv sync` only updates ./.venv.
install-cli:
	$(UV) tool install --editable '.[pdf]' --force
	$(UV) tool update-shell
	$(UV) run skuggi-init

lint:
	$(UV) run ruff check

## rewrites files; `make check` verifies instead
format:
	$(UV) run ruff format
	$(UV) run ruff check --fix

typecheck:
	$(UV) run mypy

test:
	$(UV) run pytest

## talks to real providers, costs money, needs credentials. Never part of `check`.
## --no-cov: a partial selection would trip the global --cov-fail-under=90 and
## exit non-zero even when every selected test passes.
eval:
	$(UV) run pytest -m eval --no-cov

## drives the real pipeline against the FROZEN e2e fixture target (bring it up
## first: `docker compose -f tests/e2e/fixtures/lab/docker-compose.yml up -d --wait`).
## Skips cleanly when the fixture is down. This target is separate from the
## user-facing labs/ range (see the lab-* targets). --no-cov as `eval`; never in `check`.
e2e:
	$(UV) run pytest -m e2e --no-cov

## Practice-range control (labs/). `LAB=` takes a lab id, e.g. 01-trivial-goat-cms.
##   make lab-list                       # every lab, its tier, ports and up/down state
##   make lab-up LAB=01-trivial-goat-cms  # build + start a lab (loopback-only)
##   make lab-down LAB=...                # stop, keeping planted data
##   make lab-restore LAB=...             # revert the TARGET to pristine, keep your work
##   make lab-wipe LAB=...                # nuke the target AND ./engagements/<lab>
##   make lab-verify LAB=...              # assert the manifest's planted loot is present
lab-list:
	$(LABCTL) list
lab-up:
	$(LABCTL) up $(LAB)
lab-down:
	$(LABCTL) down $(LAB)
lab-restore:
	$(LABCTL) restore $(LAB)
lab-wipe:
	$(LABCTL) wipe $(LAB)
lab-verify:
	$(LABCTL) verify $(LAB)

## The deterministic eval tier as a standalone offline gate (no provider, no
## network): score compliance/methodology/schema/result_compat vs evals/baseline.json
## and fail on regression. Also runs inside `make check` via the tests/eval_det suite.
eval-det:
	$(UV) run skuggi-eval --tier det --check

## The full eval benchmark: adds the quality tier (factuality, budget, latency)
## across the configured model matrix (evals/models.json), flags cross-model
## divergence as a regression, and regenerates evals/scorecard.md. Costs money;
## needs credentials. Framework-free and local: nothing is uploaded, and the
## judge is skuggi's own provider-agnostic model.
bench:
	$(UV) run skuggi-eval --tier all --suite full --check --scorecard evals/scorecard.md

## The cheap quality signal: the `fast` suite -- a curated case subset graded by a
## single model -- without the full matrix. Costs money; needs a credential.
bench-fast:
	$(UV) run skuggi-eval --tier quality --suite fast

## The gate. Same commands, same order as .github/workflows/ci.yml.
## `ruff format --check` and never `ruff format`: a target that rewrites files
## can never fail, so it can never gate anything.
check:
	$(UV) run ruff format --check
	$(UV) run ruff check
	$(UV) run python scripts/check_file_size.py
	$(UV) run mypy
	$(UV) run pytest

## render a Markdown file to a styled PDF: `make pdf IN=docs/architecture.md`
## needs the `pdf` group (make install) and a system Pango (brew install pango)
pdf:
	$(UV) run skuggi-pdf $(IN)

## Refresh the vendored framework taxonomies (WSTG/ATT&CK/PTES) from upstream at
## their pins and rewrite src/skuggi/frameworks/data/*.json. Maintainer-only (hits
## the network); commit the result. `make frameworks CHECK=1` only reports drift.
frameworks:
	$(UV) run python scripts/sync_frameworks.py all $(if $(CHECK),--check,)

clean:
	rm -rf .ruff_cache .mypy_cache .pytest_cache htmlcov coverage.xml .coverage dist *.egg-info

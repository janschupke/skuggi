UV ?= uv

.PHONY: install lint format typecheck test eval e2e eval-det bench check clean pdf

## sync the locked environment and install the git hooks
install:
	$(UV) sync --all-groups
	$(UV) run pre-commit install
	$(UV) run pre-commit install --hook-type pre-push

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

## drives the real pipeline against the docker lab (bring it up first:
## `cd lab && docker compose up -d --wait`). Skips cleanly when the lab is down.
## --no-cov for the same reason as `eval`. Never part of `check`.
e2e:
	$(UV) run pytest -m e2e --no-cov

## The deterministic eval tier as a standalone offline gate (no provider, no
## network): score compliance/methodology/schema/result_compat vs evals/baseline.json
## and fail on regression. Also runs inside `make check` via the tests/eval_det suite.
eval-det:
	$(UV) run skuggi-eval --tier det --check

## The full eval benchmark across providers: adds the quality tier (factuality,
## budget, latency) and regenerates evals/scorecard.md. Costs money; needs
## credentials. Every Braintrust Eval runs local (no_send_logs); nothing uploads.
bench:
	$(UV) run skuggi-eval --tier all --provider openai --provider anthropic \
		--check --scorecard evals/scorecard.md

## The gate. Same commands, same order as .github/workflows/ci.yml.
## `ruff format --check` and never `ruff format`: a target that rewrites files
## can never fail, so it can never gate anything.
check:
	$(UV) run ruff format --check
	$(UV) run ruff check
	$(UV) run mypy
	$(UV) run pytest

## render a Markdown file to a styled PDF: `make pdf IN=docs/architecture.md`
## needs the `pdf` group (make install) and a system Pango (brew install pango)
pdf:
	$(UV) run skuggi-pdf $(IN)

clean:
	rm -rf .ruff_cache .mypy_cache .pytest_cache htmlcov coverage.xml .coverage dist *.egg-info

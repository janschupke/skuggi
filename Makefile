UV ?= uv

.PHONY: install lint format typecheck test eval e2e check clean pdf

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

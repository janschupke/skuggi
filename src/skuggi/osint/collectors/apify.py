"""The Apify actor runner (optional extra, pluggable scraper backend).

Apify is an alternative backend for the browser-driven sources (LinkedIn/ATS/
social): when an ``apify_token`` and a per-source ``apify_actor`` are configured, a
collector runs the actor and reads its dataset instead of driving a local browser.
The client is imported lazily so the base install still runs; ``apify_available``
gates on both the token and the package.
"""

from __future__ import annotations

import importlib.util
from collections.abc import Mapping

from skuggi.common.logs import get_logger
from skuggi.intel.collectors.base import ApifyRun

log = get_logger(__name__)


def apify_installed() -> bool:
    """Whether the optional ``apify-client`` package is importable (no import)."""
    return importlib.util.find_spec("apify_client") is not None


def make_apify_run(token: str) -> ApifyRun | None:
    """An :data:`ApifyRun` bound to ``token``, or None when unusable.

    Returns None when the token is empty or the client is not installed, so the
    core simply leaves ``CollectContext.apify_run`` unset and the Apify path stays
    off. The returned runner is best-effort: any client error yields ``None``.
    """
    if not token or not apify_installed():
        return None

    def run(
        actor_id: str, run_input: Mapping[str, object]
    ) -> list[dict[str, object]] | None:
        from apify_client import ApifyClient  # noqa: PLC0415 -- optional dep

        try:
            client = ApifyClient(token)
            run_info = client.actor(actor_id).call(run_input=dict(run_input))
            if not run_info:
                return None
            # apify-client 3.x returns a pydantic ``Run`` model (no ``.get``);
            # the dataset id is the ``default_dataset_id`` field (REST alias
            # ``defaultDatasetId``). ``.get(...)`` was both a mypy error under
            # ``--all-extras`` and a runtime AttributeError.
            dataset_id = str(getattr(run_info, "default_dataset_id", "") or "")
            if not dataset_id:
                return None
            return list(client.dataset(dataset_id).iterate_items())
        except Exception:
            log.warning("apify actor %r failed", actor_id, exc_info=True)
            return None

    return run

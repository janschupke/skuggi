"""Turn operator-facing setup failures into a clean exit, not a traceback.

``skuggi`` and ``skuggi-repl`` build an :class:`~skuggi.core.AgentCore` at
startup. A missing credential or other setup problem should print one
actionable line and exit, not bury it under a Python traceback. Set
``SKUGGI_DEBUG`` to get the traceback back for debugging.
"""

from __future__ import annotations

import os
import sys
from collections.abc import Callable

from skuggi.configs import ConfigError


def _is_setup_error(exc: BaseException) -> bool:
    """Whether `exc` is a known, actionable operator-facing setup failure.

    ``ConfigError`` (bad config / missing credential) and ``ImportError`` (a
    provider SDK that is not installed) are the common, cheap cases. A
    ``CodexAuthError`` only arises for the chatgpt provider, and reaching for
    its class imports the OpenAI SDK with it -- so it is checked last, and only
    once we already have an unexpected error, never on the happy path.
    """
    if isinstance(exc, (ConfigError, ImportError)):
        return True
    from skuggi.codex_chat import CodexAuthError  # noqa: PLC0415

    return isinstance(exc, CodexAuthError)


def guard_boot[T](build: Callable[[], T]) -> T:
    """Run `build()`; on a known setup error, print it plainly and exit 1.

    Anything that is not a recognised setup error -- a genuine bug -- is
    re-raised untouched so it still surfaces a full traceback.
    """
    try:
        return build()
    except Exception as exc:
        if os.environ.get("SKUGGI_DEBUG") or not _is_setup_error(exc):
            raise
        print(f"skuggi: {exc}", file=sys.stderr)
        raise SystemExit(1) from exc

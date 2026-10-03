"""The fail-closed assertion that no un-redacted secret reached the model.

Ingress redaction (in the graph) is the *mechanism* that keeps secrets out of a
request; this is the *guarantee*. ``assert_clean`` re-scans a fully assembled
model-bound string and, if any detector still fires, treats it as a leak.

Two postures share one scanner:

* tests (and the egress funnel under a strict flag) call ``assert_clean``, which
  **raises** ``RedactionLeakError`` -- a leak must fail the suite, loudly, not slip by.
* the live funnel calls ``scrub`` as a last resort, which masks whatever
  survived and logs it, so a detector gap degrades to an over-mask rather than a
  disclosure.
"""

from __future__ import annotations

from skuggi.common.logs import get_logger
from skuggi.security.policy import RedactionPolicy
from skuggi.security.redaction import redact, scan

log = get_logger(__name__)


class RedactionLeakError(RuntimeError):
    """A secret/PII value survived redaction and reached a model-bound string."""


def assert_clean(text: str, policy: RedactionPolicy) -> None:
    """Raise ``RedactionLeakError`` if any sensitive span remains in `text`.

    The error names the kinds that leaked but never echoes the values -- an
    assertion message is itself a surface a secret must not reach.
    """
    residual = scan(text, policy)
    if residual:
        kinds = sorted({match.kind for match in residual})
        msg = f"redaction leak: {len(residual)} unmasked span(s), kinds={kinds}"
        raise RedactionLeakError(msg)


def scrub(text: str, policy: RedactionPolicy) -> str:
    """Mask any sensitive span that survived earlier redaction, and log it.

    The production last line: a one-way mask (no interner), so a detector that
    only fires on fully-assembled context cannot leak. Returns `text` unchanged
    when it is already clean.
    """
    residual = scan(text, policy)
    if not residual:
        return text
    kinds = sorted({match.kind for match in residual})
    log.warning(
        "egress redaction net caught %d unmasked span(s): kinds=%s",
        len(residual),
        kinds,
    )
    return redact(text, policy)

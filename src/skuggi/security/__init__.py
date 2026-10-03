"""The data-plane boundary: keep secrets and PII out of the model context.

skuggi feeds command output, retrieved documents and prior findings back to the
LLM. Any of those can carry a credential, a token or personal data lifted from a
target. This package is the one deterministic boundary that scrubs that content
before it crosses into a provider request:

- ``redaction`` -- pure, rule-based detectors that turn each secret/PII value
  into a stable placeholder (``«KIND:id»``). No model, no network, no I/O.
- ``vault`` -- the per-engagement store mapping a placeholder back to its real
  value, so the harness can *rehydrate* a value into a command it runs for a
  tool without the value ever reaching the model.
- ``policy`` -- what to scrub and the scope values that must pass through
  untouched (the agent has to reason about its own in-scope targets).
- ``tripwire`` -- the fail-closed assertion that no un-redacted secret survived,
  used as a hard gate in tests and a last-resort mask in production.

The design is a data plane / control plane split: the model reasons over
handles and redacted summaries (control plane); the raw values live in files and
the vault and reach tools only (data plane).
"""

from __future__ import annotations

from skuggi.security.policy import RedactionPolicy
from skuggi.security.redaction import REDACTED, Interner, redact, scan
from skuggi.security.tripwire import RedactionLeakError, assert_clean
from skuggi.security.vault import SecretVault

__all__ = [
    "REDACTED",
    "Interner",
    "RedactionLeakError",
    "RedactionPolicy",
    "SecretVault",
    "assert_clean",
    "redact",
    "scan",
]

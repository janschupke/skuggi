"""The Burp Suite connector: drive Burp and read results back as findings.

Burp is driven over a bridge extension running inside it (Proxy/Repeater/Intruder/
Scanner). The package layers like :mod:`skuggi.intel` + :mod:`skuggi.osint`:

* :mod:`skuggi.burp.models` -- backend-agnostic Burp value objects.
* :mod:`skuggi.burp.client` -- the ``BurpClient`` protocol + the reburp REST adapter.
* :mod:`skuggi.burp.findings` -- scanner issue -> ``FindingDraft`` mapping.

The write plane (repeater/intruder/active-scan) is gated by
:mod:`skuggi.engagement.burp_guard` and recorded in the ledger ``burp_actions``
table; the read plane (proxy history, scan issues) flows to the shared finding
sink. See ``docs`` / the plan for the full design.
"""

from __future__ import annotations

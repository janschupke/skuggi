"""Security-framework awareness: deterministic CVSS scoring + vendored taxonomies.

The vendored, version-pinned taxonomy data covers OWASP WSTG, MITRE ATT&CK and PTES.
The design rule for this package: *computation is code, assessment is input*. The
CVSS score is produced entirely by :mod:`skuggi.frameworks.cvss` from a vector
string -- no model, no network -- so a stored vector reconstructs its numbers
exactly. The taxonomy data is vendored and pinned (see ``data/`` + the sync
script) so lookups are offline and cannot drift between releases.
"""

from __future__ import annotations

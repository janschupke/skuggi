"""The one shared verbosity flag for every verb's output.

``-v`` / ``--verbose`` is accepted *everywhere* (stripped by ``pop_verbose`` so it
never errors on a verb that has no detailed mode) and *honored* by the outputs
that have a compact-vs-full distinction -- ``cmd``, ``help``, ``show tools`` and
``doctor``. Keeping the parse in one place means a new verb opts in simply by
calling ``pop_verbose`` on its argument string.
"""

from __future__ import annotations

_FLAGS = frozenset({"-v", "--verbose"})


def pop_verbose(rest: str) -> tuple[bool, str]:
    """Split a ``-v``/``--verbose`` flag out of `rest`.

    Returns ``(verbose, cleaned)`` where `cleaned` is `rest` with every verbosity
    flag token removed (and surrounding whitespace collapsed). The flag may appear
    anywhere in the argument string, so ``cmd -v nmap`` and ``cmd nmap -v`` are
    equivalent.
    """
    tokens = rest.split()
    verbose = any(t in _FLAGS for t in tokens)
    cleaned = " ".join(t for t in tokens if t not in _FLAGS)
    return verbose, cleaned

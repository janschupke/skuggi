"""Console entry point for the REPL (``skuggi-repl``).

The default ``skuggi`` command is the shell wrapper (``skuggi.shell``); this is
the pure agent chat, kept for when you want the REPL without a wrapped shell.
"""

from skuggi.boot import guard_boot
from skuggi.config import Settings
from skuggi.tui import Tui


def main() -> None:
    """Launch the REPL."""
    # Only the construction is guarded -- a mid-session error must not be
    # swallowed as a setup failure.
    app = guard_boot(lambda: Tui(Settings()))
    app.run()


if __name__ == "__main__":
    main()

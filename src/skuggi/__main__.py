"""Console entry point for the REPL (``skuggi-repl``).

The default ``skuggi`` command is the shell wrapper (``skuggi.shell``); this is
the pure agent chat, kept for when you want the REPL without a wrapped shell.
"""

from skuggi.config import Settings
from skuggi.tui import Tui


def main() -> None:
    """Launch the REPL."""
    Tui(Settings()).run()


if __name__ == "__main__":
    main()

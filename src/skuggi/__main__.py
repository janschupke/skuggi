"""Console entry point for the REPL (``skuggi-repl``).

The default ``skuggi`` command is the shell wrapper (``skuggi.frontend.shell``); this is
the pure agent chat, kept for when you want the REPL without a wrapped shell.
"""

from skuggi.common.logs import get_logger, setup_logging
from skuggi.config.config import Settings
from skuggi.frontend.tui import Tui
from skuggi.install.boot import guard_boot


def main() -> None:
    """Launch the REPL."""
    setup_logging()
    get_logger(__name__).info("skuggi-repl starting")
    # Only the construction is guarded -- a mid-session error must not be
    # swallowed as a setup failure.
    app = guard_boot(lambda: Tui(Settings()))
    app.run()


if __name__ == "__main__":
    main()

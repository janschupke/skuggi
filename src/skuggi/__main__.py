"""Console entry point for the REPL."""

from skuggi.config import Settings
from skuggi.tui import Tui


def main() -> None:
    """Launch the REPL."""
    Tui(Settings()).run()


if __name__ == "__main__":
    main()

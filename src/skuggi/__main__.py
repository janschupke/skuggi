from dotenv import load_dotenv

from skuggi.tui import Tui


def main() -> None:
    load_dotenv()
    Tui().run()


if __name__ == "__main__":
    main()

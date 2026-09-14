"""Command-line entry point for BIOAEGIS."""

import argparse

from . import __version__
from .tui import run


def main() -> None:
    parser = argparse.ArgumentParser(
        prog="bioaegis",
        description="BIOAEGIS safe biological-inspired defensive prototype",
    )
    parser.add_argument("--version", action="version", version=f"BIOAEGIS {__version__}")
    parser.parse_args()
    run()


if __name__ == "__main__":
    main()

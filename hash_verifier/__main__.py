"""python -m hash_verifier → GUI; python -m hash_verifier.cli → CLI."""

import sys

from hash_verifier.cli import main as cli_main
from hash_verifier.gui import run_gui


def main() -> int:
    if len(sys.argv) > 1:
        return cli_main()
    run_gui()
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

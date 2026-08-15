"""Command-line entry point: ``python -m openagentfence [trace.json]``.

Prints a short, sanitized summary of a security trace. It never dumps the trace
document, so values stored under secret-bearing keys cannot reach stdout through
this path.
"""

from __future__ import annotations

import argparse
import sys
from collections.abc import Sequence

from . import __version__
from .trace import DEFAULT_MAX_BYTES, Trace, TraceError

_PROG = "openagentfence"


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog=_PROG,
        description=(
            "Print a redacted summary of an OpenAgentFence security trace. "
            "Python interoperability tooling; not the OpenAgentFence runtime."
        ),
    )
    parser.add_argument(
        "--version",
        action="version",
        version=f"{_PROG} {__version__}",
    )
    parser.add_argument(
        "--max-bytes",
        type=int,
        default=DEFAULT_MAX_BYTES,
        metavar="N",
        help=f"refuse traces larger than N bytes (default: {DEFAULT_MAX_BYTES})",
    )
    parser.add_argument(
        "path",
        metavar="TRACE",
        help="path to a JSON security trace",
    )
    return parser


def main(argv: Sequence[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)

    if args.max_bytes <= 0:
        parser.error("--max-bytes must be positive")

    try:
        trace = Trace.load(args.path, max_bytes=args.max_bytes)
    except TraceError as error:
        print(f"{_PROG}: {error}", file=sys.stderr)
        return 1

    print(trace.summary())
    return 0


if __name__ == "__main__":  # pragma: no cover - exercised via subprocess
    sys.exit(main())

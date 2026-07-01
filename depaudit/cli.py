"""Command-line interface for depaudit."""

from __future__ import annotations

import argparse
from collections.abc import Sequence
from pathlib import Path

from depaudit.models import Dependency
from depaudit.parsers import parse_environment, parse_pyproject, parse_requirements


def _format_table(deps: Sequence[Dependency]) -> str:
    """Render dependencies as a simple aligned text table."""
    if not deps:
        return "No dependencies found."
    name_w = max(len("NAME"), *(len(d.name) for d in deps))
    ver_w = max(len("VERSION"), *(len(d.version or "-") for d in deps))
    rows = [f"{'NAME':<{name_w}}  {'VERSION':<{ver_w}}  SOURCE"]
    rows += [f"{d.name:<{name_w}}  {(d.version or '-'):<{ver_w}}  {d.source}" for d in deps]
    rows.append(f"\n{len(deps)} dependencies")
    return "\n".join(rows)


def build_parser() -> argparse.ArgumentParser:
    """Construct the argument parser for the ``depaudit`` command."""
    parser = argparse.ArgumentParser(
        prog="depaudit",
        description="Audit Python dependencies for supply-chain risk.",
    )
    sub = parser.add_subparsers(dest="command", required=True)

    p_parse = sub.add_parser(
        "parse", help="List dependencies from a requirements file or the environment."
    )
    p_parse.add_argument(
        "path", nargs="?", help="Path to a requirements.txt-style file or a pyproject.toml."
    )
    p_parse.add_argument(
        "--env",
        action="store_true",
        help="Read the active Python environment instead of a file.",
    )
    return parser


def main(argv: Sequence[str] | None = None) -> int:
    """Entry point. Returns a process exit code."""
    parser = build_parser()
    args = parser.parse_args(argv)

    if args.command == "parse":
        if args.env:
            deps = parse_environment()
        elif args.path:
            if Path(args.path).name == "pyproject.toml":
                deps = parse_pyproject(args.path)
            else:
                deps = parse_requirements(args.path)
        else:
            parser.error("provide a requirements file path or use --env")
        print(_format_table(deps))
        return 0

    parser.error(f"unknown command: {args.command}")  # pragma: no cover
    return 2


if __name__ == "__main__":  # pragma: no cover
    raise SystemExit(main())

"""Dependency parsers for depaudit.

Public API is re-exported here so callers use ``from depaudit.parsers import ...``
regardless of which submodule a given parser lives in.
"""

from __future__ import annotations

from pathlib import Path

from depaudit.models import Dependency
from depaudit.parsers._normalize import normalize_name
from depaudit.parsers.environment import parse_environment
from depaudit.parsers.pyproject import parse_pyproject
from depaudit.parsers.requirements import parse_requirements

__all__ = [
    "load_dependencies",
    "normalize_name",
    "parse_environment",
    "parse_pyproject",
    "parse_requirements",
]


def load_dependencies(path: str | None, *, env: bool) -> list[Dependency]:
    """Load dependencies from a source, dispatching by kind.

    Central entry point shared by the CLI and the MCP server so both resolve a
    dependency source identically. Exactly one source is used, in priority order:
    the active environment, then a file path (a ``pyproject.toml`` by name, else a
    requirements-style file).

    Args:
        path: Path to a ``requirements.txt``-style file or a ``pyproject.toml``.
            Ignored when ``env`` is true.
        env: Read the active Python environment instead of a file.

    Returns:
        The parsed dependencies (possibly empty). The underlying parsers are
        best-effort and skip malformed entries rather than raising.

    Raises:
        ValueError: If neither ``env`` nor ``path`` is provided.
    """
    if env:
        return parse_environment()
    if path:
        if Path(path).name == "pyproject.toml":
            return parse_pyproject(path)
        return parse_requirements(path)
    raise ValueError("provide a requirements file path or set env=True")

"""Parse dependencies from a PEP 621 ``pyproject.toml``."""

from __future__ import annotations

import sys
from pathlib import Path

from depaudit.models import Dependency
from depaudit.parsers.requirements import dependency_from_requirement

if sys.version_info >= (3, 11):
    import tomllib
else:  # pragma: no cover - exercised only on Python 3.10
    try:
        import tomli as tomllib
    except ImportError:
        tomllib = None


def parse_pyproject(path: str | Path) -> list[Dependency]:
    """Parse a PEP 621 ``pyproject.toml`` into :class:`Dependency` records.

    Reads ``[project].dependencies`` and every group under
    ``[project.optional-dependencies]`` (in sorted group order). Each entry is a PEP 508
    requirement string parsed the same way as a ``requirements.txt`` line: extras are
    ignored, markers/comments stripped, and ``==`` pins become concrete versions.

    Best-effort and conservative: entries that aren't strings or don't yield a name are
    skipped, and malformed TOML yields an empty list rather than raising. Poetry-style
    ``[tool.poetry.dependencies]`` tables are intentionally not read — only the standard
    ``[project]`` metadata. Duplicates across groups are preserved, not merged.

    Raises:
        RuntimeError: If no TOML parser is available (Python < 3.11 without ``tomli``).
    """
    if tomllib is None:  # pragma: no cover - exercised only on Python 3.10
        raise RuntimeError(
            "parsing pyproject.toml requires Python 3.11+ (tomllib) or the 'tomli' package"
        )

    path = Path(path)
    try:
        data = tomllib.loads(path.read_text(encoding="utf-8"))
    except (tomllib.TOMLDecodeError, UnicodeDecodeError):
        return []

    project = data.get("project")
    if not isinstance(project, dict):
        return []

    deps: list[Dependency] = []
    deps.extend(_deps_from_list(project.get("dependencies"), source=path.name))

    optional = project.get("optional-dependencies")
    if isinstance(optional, dict):
        for group in sorted(optional):
            deps.extend(_deps_from_list(optional[group], source=path.name))

    return deps


def _deps_from_list(entries: object, source: str) -> list[Dependency]:
    """Turn a TOML value expected to be a list of requirement strings into dependencies.

    Non-list values and non-string entries are skipped rather than raising, since the
    file is untrusted input.
    """
    if not isinstance(entries, list):
        return []
    deps: list[Dependency] = []
    for entry in entries:
        if not isinstance(entry, str):
            continue
        dep = dependency_from_requirement(entry, source=source)
        if dep is not None:
            deps.append(dep)
    return deps

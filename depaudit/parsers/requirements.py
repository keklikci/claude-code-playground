"""Parse dependencies from pip requirements files."""

from __future__ import annotations

import re
from pathlib import Path

from depaudit.models import Dependency
from depaudit.parsers._normalize import normalize_name

# Capture the distribution name and the trailing version specifier, stopping at an
# environment marker (";") or inline comment ("#"). Extras like "[security]" are skipped.
_REQ_RE = re.compile(
    r"^\s*(?P<name>[A-Za-z0-9][A-Za-z0-9._-]*)"
    r"(?:\[[^\]]+\])?"          # optional extras, ignored
    r"\s*(?P<spec>[^;#]*)"      # version specifier up to a marker or comment
)

# An exact "==" pin, e.g. "==1.4.2".
_PIN_RE = re.compile(r"^==(?P<v>[A-Za-z0-9][A-Za-z0-9.\-_+!]*)$")


def _exact_version(spec: str) -> str | None:
    """Return the concrete version if ``spec`` is an exact ``==`` pin, else ``None``."""
    match = _PIN_RE.match(spec.replace(" ", ""))
    return match.group("v") if match else None


def parse_requirements(path: str | Path) -> list[Dependency]:
    """Parse a pip requirements file into :class:`Dependency` records.

    Best-effort and intentionally conservative: blank lines, comments, option lines
    (``-r``, ``-e``, ``--hash``), and direct URL/VCS references are skipped. Environment
    markers and inline comments are stripped from the specifier.
    """
    path = Path(path)
    deps: list[Dependency] = []
    for raw_line in path.read_text(encoding="utf-8").splitlines():
        line = raw_line.strip()
        if not line or line.startswith("#"):
            continue
        if line.startswith("-"):  # -r / -e / --hash and other options
            continue
        if "://" in line:  # direct URL or VCS reference
            continue
        match = _REQ_RE.match(line)
        if not match:
            continue
        spec = match.group("spec").strip()
        deps.append(
            Dependency(
                name=normalize_name(match.group("name")),
                version=_exact_version(spec),
                specifier=spec,
                source=path.name,
            )
        )
    return deps

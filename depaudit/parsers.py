"""Parse dependencies from requirements files and the installed environment."""

from __future__ import annotations

import re
from importlib import metadata
from pathlib import Path

from depaudit.models import Dependency

_NORMALIZE_RE = re.compile(r"[-_.]+")

# Capture the distribution name and the trailing version specifier, stopping at an
# environment marker (";") or inline comment ("#"). Extras like "[security]" are skipped.
_REQ_RE = re.compile(
    r"^\s*(?P<name>[A-Za-z0-9][A-Za-z0-9._-]*)"
    r"(?:\[[^\]]+\])?"          # optional extras, ignored
    r"\s*(?P<spec>[^;#]*)"      # version specifier up to a marker or comment
)

# An exact "==" pin, e.g. "==1.4.2".
_PIN_RE = re.compile(r"^==(?P<v>[A-Za-z0-9][A-Za-z0-9.\-_+!]*)$")


def normalize_name(name: str) -> str:
    """Normalize a distribution name per PEP 503 (lowercase, runs of -_. -> single -)."""
    return _NORMALIZE_RE.sub("-", name).strip().lower()


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


def parse_environment() -> list[Dependency]:
    """Read installed distributions from the active Python environment, sorted by name."""
    seen: set[str] = set()
    deps: list[Dependency] = []
    for dist in metadata.distributions():
        raw_name = dist.metadata["Name"]
        if not raw_name:
            continue
        name = normalize_name(raw_name)
        if name in seen:  # editable + regular installs can both appear
            continue
        seen.add(name)
        version = dist.version
        deps.append(
            Dependency(
                name=name,
                version=version,
                specifier=f"=={version}" if version else "",
                source="environment",
            )
        )
    return sorted(deps, key=lambda d: d.name)

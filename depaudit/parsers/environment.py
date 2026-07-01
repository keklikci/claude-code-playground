"""Parse dependencies from the installed Python environment."""

from __future__ import annotations

from importlib import metadata

from depaudit.models import Dependency
from depaudit.parsers._normalize import normalize_name


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

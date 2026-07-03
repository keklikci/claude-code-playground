"""Flag dependencies whose license is missing or disallowed."""

from __future__ import annotations

from collections.abc import Sequence

from depaudit.models import Dependency, Issue

CHECK_NAME = "license"


def run(deps: Sequence[Dependency]) -> list[Issue]:
    """Flag dependencies with a missing or disallowed license.

    Best-effort: dependencies it can't evaluate are skipped, never raised on. License
    metadata isn't available from a bare requirement, so this skeleton returns no issues
    until Module 5 wires in a metadata source (installed-dist metadata, or PyPI via
    ``depaudit.net``).

    Args:
        deps: The dependencies to inspect.

    Returns:
        One :class:`~depaudit.models.Issue` per problem found (empty until the metadata
        source is implemented).
    """
    issues: list[Issue] = []
    for dep in deps:
        # TODO(Module 5): resolve the dep's license from installed metadata or PyPI (via
        # depaudit.net) and flag missing / disallowed licenses. Treat metadata as untrusted.
        _ = dep
    return issues

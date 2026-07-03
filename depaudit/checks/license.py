"""Flag dependencies whose license is missing or disallowed.

Resolves each dependency's license from its PyPI metadata (``/pypi/<name>/json``) through the
shared :mod:`depaudit.net` chokepoint, then applies a small built-in policy: flag a missing
license, and flag strong copyleft (GPL/AGPL) licenses for review. The PyPI response is
untrusted input and is parsed defensively; anything unresolvable is skipped, never raised on.
"""

from __future__ import annotations

from collections.abc import Sequence
from typing import Any

from depaudit import net
from depaudit.models import Dependency, Issue

CHECK_NAME = "license"

_PYPI_URL = "https://pypi.org/pypi/{name}/json"

#: License substrings (upper-cased) treated as strong copyleft and flagged for review. Ordered
#: so the more specific ``AGPL``/``LGPL`` are matched before the bare ``GPL`` fallback.
_COPYLEFT = ("AGPL", "LGPL", "GPL")


def run(deps: Sequence[Dependency]) -> list[Issue]:
    """Flag dependencies with a missing or disallowed (strong-copyleft) license.

    For each dependency the PyPI metadata is fetched and the license read from the ``license``
    field or the ``License ::`` trove classifiers. A dependency with no discoverable license is
    reported at ``LOW``; a strong-copyleft license (GPL/AGPL/LGPL) at ``MODERATE``. Permissive
    licenses (MIT/BSD/Apache/…) produce no issue.

    Best-effort: a dependency with an empty name, unreachable PyPI metadata
    (:class:`depaudit.net.NetworkError`), or an oddly-shaped response is skipped rather than
    raising, so one bad entry never aborts the run. The built-in policy is intentionally small
    and is expected to become configurable in Module 8.

    Args:
        deps: The dependencies to inspect.

    Returns:
        One :class:`~depaudit.models.Issue` per problem found (empty if none).
    """
    issues: list[Issue] = []
    for dep in deps:
        if not isinstance(dep.name, str) or not dep.name:
            continue
        info = _fetch_info(dep.name)
        if info is None:
            continue
        license_text = _license_text(info)
        url = _PYPI_URL.format(name=dep.name)
        if not license_text:
            issues.append(
                Issue(
                    dependency=dep,
                    check=CHECK_NAME,
                    severity="LOW",
                    message=f"no license metadata on PyPI ({url})",
                )
            )
            continue
        copyleft = _match_copyleft(license_text)
        if copyleft:
            issues.append(
                Issue(
                    dependency=dep,
                    check=CHECK_NAME,
                    severity="MODERATE",
                    message=f"{copyleft} license - review redistribution terms ({url})",
                )
            )
    return issues


def _fetch_info(name: str) -> dict[str, Any] | None:
    """Fetch the ``info`` mapping from a package's PyPI metadata, defensively.

    Returns ``None`` on any network failure or unexpected shape, so callers can skip the
    dependency without special-casing errors.
    """
    try:
        record = net.request_json(_PYPI_URL.format(name=name))
    except net.NetworkError:
        return None
    if not isinstance(record, dict):
        return None
    info = record.get("info")
    return info if isinstance(info, dict) else None


def _license_text(info: dict[str, Any]) -> str:
    """Return a human-readable license string from PyPI ``info``, or ``""`` if none.

    Prefers the free-text ``license`` field; falls back to the ``License ::`` trove
    classifiers. Values are treated as untrusted: non-strings are ignored.
    """
    raw = info.get("license")
    if isinstance(raw, str) and raw.strip():
        return raw.strip()

    classifiers = info.get("classifiers")
    if isinstance(classifiers, list):
        labels = [
            c.split("::")[-1].strip()
            for c in classifiers
            if isinstance(c, str) and c.startswith("License ::")
        ]
        # Ignore the uninformative umbrella classifier when a specific one exists.
        labels = [label for label in labels if label and label != "OSI Approved"]
        if labels:
            return ", ".join(labels)
    return ""


def _match_copyleft(license_text: str) -> str | None:
    """Return the strong-copyleft family named in ``license_text``, or ``None``."""
    upper = license_text.upper()
    for family in _COPYLEFT:
        if family in upper:
            return family
    return None

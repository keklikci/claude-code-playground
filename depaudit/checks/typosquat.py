"""Flag dependencies whose names resemble a popular package (possible typosquatting).

Typosquatting is a supply-chain attack where a malicious package is published under a name
one edit away from a widely used one (``requsts`` for ``requests``, ``python-dateutil`` vs
``python-datetutil``) hoping to catch typos. This check compares each dependency name against
a bundled snapshot of popular PyPI names (:data:`depaudit.data.popular_packages.POPULAR`) and
flags near-misses. It is pure and local: no network, no I/O.
"""

from __future__ import annotations

from collections.abc import Sequence

from depaudit.data.popular_packages import POPULAR
from depaudit.models import Dependency, Issue
from depaudit.parsers import normalize_name

CHECK_NAME = "typosquat"


def run(deps: Sequence[Dependency]) -> list[Issue]:
    """Flag dependencies whose name is one edit away from a popular package.

    Exact matches are legitimate (the dependency *is* the popular package) and produce no
    issue. A name within Levenshtein distance 1 of some popular name — but not equal to any —
    is reported as a possible typosquat at ``MODERATE`` severity, since edit-distance-1 also
    catches innocent forks and shortenings; treat it as a prompt to verify, not a verdict.

    Best-effort: entries with a missing or non-string name are skipped, never raised on.

    Args:
        deps: The dependencies to inspect.

    Returns:
        One :class:`~depaudit.models.Issue` per suspected typosquat (empty if none).
    """
    issues: list[Issue] = []
    for dep in deps:
        name = dep.name
        if not isinstance(name, str) or not name:
            continue
        name = normalize_name(name)
        if name in POPULAR:
            continue
        target = _nearest_within_one(name)
        if target is not None:
            issues.append(
                Issue(
                    dependency=dep,
                    check=CHECK_NAME,
                    severity="MODERATE",
                    message=(
                        f"'{name}' resembles popular package '{target}' "
                        "(edit distance 1) - verify it is the intended dependency"
                    ),
                )
            )
    return issues


def _nearest_within_one(name: str) -> str | None:
    """Return a popular name within edit distance 1 of ``name``, or ``None``.

    Returns the first match found; the popular set is small enough that a linear scan is
    fine and the exact representative doesn't matter for the warning.
    """
    for candidate in POPULAR:
        if _within_distance_one(name, candidate):
            return candidate
    return None


def _within_distance_one(a: str, b: str) -> bool:
    """Whether ``a`` and ``b`` are within Levenshtein distance 1 (one indel or substitution).

    Pure-stdlib and cheap: identical strings and length differences greater than one are
    decided immediately; otherwise at most a single edit is allowed while walking the pair.
    """
    if a == b:
        return True
    la, lb = len(a), len(b)
    if abs(la - lb) > 1:
        return False

    if la == lb:
        # Same length: at most one substitution.
        diffs = sum(1 for ca, cb in zip(a, b, strict=True) if ca != cb)
        return diffs == 1

    # Lengths differ by exactly one: the longer must equal the shorter with one char inserted.
    shorter, longer = (a, b) if la < lb else (b, a)
    i = j = 0
    edited = False
    while i < len(shorter) and j < len(longer):
        if shorter[i] == longer[j]:
            i += 1
            j += 1
            continue
        if edited:
            return False
        edited = True
        j += 1  # skip the inserted char in the longer string
    return True

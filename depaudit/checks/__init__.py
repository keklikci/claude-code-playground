"""Dependency checks for depaudit.

A *check* inspects a list of :class:`~depaudit.models.Dependency` records and returns
:class:`~depaudit.models.Issue` records describing supply-chain problems (typosquatting,
license compliance, integrity, …). Checks are added from Module 5 on, one module per check
(``depaudit/checks/<name>.py``), each exposing ``run(deps) -> list[Issue]``.

Every check registers itself in :data:`CHECKS` so a future ``scan`` can iterate all of them
by name. See ``depaudit/checks/CLAUDE.md`` for the authoring contract; the ``/add-scanner``
skill scaffolds new checks that follow it.
"""

from __future__ import annotations

from collections.abc import Callable, Sequence

from depaudit.checks.license import run as _license_run
from depaudit.checks.typosquat import run as _typosquat_run
from depaudit.models import Dependency, Issue

#: Registry of available checks, keyed by check name. Populated by each check module and
#: appended to by the ``/add-scanner`` skill when it scaffolds a new one.
CHECKS: dict[str, Callable[[Sequence[Dependency]], list[Issue]]] = {
    "license": _license_run,
    "typosquat": _typosquat_run,
}

__all__ = ["CHECKS"]

"""Dependency parsers for depaudit.

Public API is re-exported here so callers use ``from depaudit.parsers import ...``
regardless of which submodule a given parser lives in.
"""

from __future__ import annotations

from depaudit.parsers._normalize import normalize_name
from depaudit.parsers.environment import parse_environment
from depaudit.parsers.pyproject import parse_pyproject
from depaudit.parsers.requirements import parse_requirements

__all__ = ["normalize_name", "parse_environment", "parse_pyproject", "parse_requirements"]

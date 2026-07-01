"""Distribution-name normalization (PEP 503), shared across parsers."""

from __future__ import annotations

import re

_NORMALIZE_RE = re.compile(r"[-_.]+")


def normalize_name(name: str) -> str:
    """Normalize a distribution name per PEP 503 (lowercase, runs of -_. -> single -)."""
    return _NORMALIZE_RE.sub("-", name).strip().lower()

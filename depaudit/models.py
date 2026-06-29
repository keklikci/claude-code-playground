"""Core data models for depaudit."""

from __future__ import annotations

from dataclasses import dataclass


@dataclass(frozen=True, slots=True)
class Dependency:
    """A single declared or installed dependency.

    Attributes:
        name: PEP 503-normalized distribution name (lowercase, dashes).
        version: Concrete version when known — from the environment, or from a
            ``==`` pin in a requirements file. ``None`` for unpinned requirements.
        specifier: The raw version specifier as written, e.g. ``">=2.0,<3"`` or
            ``"==1.4.2"`` (empty string if none was given).
        source: Where this dependency was discovered, e.g. ``"requirements.txt"``
            or ``"environment"``.
    """

    name: str
    version: str | None
    specifier: str
    source: str

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


@dataclass(frozen=True, slots=True)
class Finding:
    """A single known vulnerability affecting a dependency.

    Produced by the OSV.dev vulnerability engine (see :mod:`depaudit.osv`). One
    :class:`Finding` is emitted per vulnerability id per affected dependency.

    Attributes:
        dependency: The affected :class:`Dependency` (carries name, version, source).
        vuln_id: The OSV identifier, e.g. ``"GHSA-..."`` or ``"PYSEC-2021-..."``.
        aliases: Other identifiers for the same advisory, e.g. CVE ids. Empty if none.
        summary: A short human-readable summary of the vulnerability (``""`` if absent).
        severity: Coarse severity band — one of ``"CRITICAL"``, ``"HIGH"``,
            ``"MODERATE"``, ``"LOW"``, or ``"UNKNOWN"`` when it can't be determined.
        url: A link to the advisory (falls back to the OSV vulnerability page).
    """

    dependency: Dependency
    vuln_id: str
    aliases: tuple[str, ...]
    summary: str
    severity: str
    url: str

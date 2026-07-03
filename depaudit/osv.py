"""OSV.dev vulnerability engine.

Maps :class:`~depaudit.models.Dependency` records to known vulnerabilities using the
free `OSV.dev <https://osv.dev>`_ API (no key required). All HTTP goes through
:mod:`depaudit.net`; this module holds only OSV-specific request/response logic.

The flow is two-step because the batch endpoint returns ids only:

1. ``POST /v1/querybatch`` — one request for every pinned dependency; results align
   with the queries array by index and contain vulnerability ids.
2. ``GET /v1/vulns/{id}`` — fetched once per unique id for full details (severity,
   summary, references, aliases).

Every field pulled from an OSV response is treated as untrusted input: missing or
oddly-shaped values are skipped defensively rather than raising, mirroring the
best-effort idiom used by the parsers.
"""

from __future__ import annotations

from collections.abc import Sequence
from typing import Any

from depaudit import net
from depaudit.models import Dependency, Finding

ECOSYSTEM = "PyPI"
_API_BASE = "https://api.osv.dev"
_QUERYBATCH_URL = f"{_API_BASE}/v1/querybatch"

# Rank for sorting findings most-severe first; also the set of canonical band names.
_SEVERITY_RANK = {"CRITICAL": 0, "HIGH": 1, "MODERATE": 2, "LOW": 3, "UNKNOWN": 4}
_SUMMARY_MAX = 100


def scan_dependencies(
    deps: Sequence[Dependency], *, timeout: float = net.DEFAULT_TIMEOUT
) -> list[Finding]:
    """Query OSV.dev for vulnerabilities affecting ``deps``.

    Only dependencies with a concrete ``version`` are queried; unpinned entries can't
    be matched against OSV and are silently skipped (the CLI reports the count).

    Args:
        deps: Dependencies to check.
        timeout: Per-request timeout in seconds, forwarded to :mod:`depaudit.net`.

    Returns:
        Findings sorted most-severe first, then by package name and vulnerability id.
        Empty if nothing is affected.

    Raises:
        depaudit.net.NetworkError: If OSV.dev is unreachable or returns malformed data.
    """
    pinned = [d for d in deps if d.version]
    if not pinned:
        return []

    payload = {
        "queries": [
            {"package": {"name": d.name, "ecosystem": ECOSYSTEM}, "version": d.version}
            for d in pinned
        ]
    }
    batch = net.request_json(_QUERYBATCH_URL, method="POST", payload=payload, timeout=timeout)
    results = batch.get("results") if isinstance(batch, dict) else None
    if not isinstance(results, list):
        return []

    cache: dict[str, dict[str, Any] | None] = {}
    findings: list[Finding] = []
    for dep, result in zip(pinned, results, strict=False):
        if not isinstance(result, dict):
            continue
        for vuln_id in _vuln_ids(result):
            record = _fetch_vuln(vuln_id, cache, timeout=timeout)
            if record is not None:
                findings.append(_finding_from_vuln(dep, record))

    findings.sort(key=lambda f: (_SEVERITY_RANK.get(f.severity, 4), f.dependency.name, f.vuln_id))
    return findings


def _vuln_ids(result: dict[str, Any]) -> list[str]:
    """Extract vulnerability ids from one querybatch result, defensively."""
    vulns = result.get("vulns")
    if not isinstance(vulns, list):
        return []
    ids: list[str] = []
    for vuln in vulns:
        if isinstance(vuln, dict) and isinstance(vuln.get("id"), str):
            ids.append(vuln["id"])
    return ids


def _fetch_vuln(
    vuln_id: str, cache: dict[str, dict[str, Any] | None], *, timeout: float
) -> dict[str, Any] | None:
    """Fetch a full vuln record by id, caching by id so shared CVEs aren't refetched."""
    if vuln_id in cache:
        return cache[vuln_id]
    record = net.request_json(f"{_API_BASE}/v1/vulns/{vuln_id}", timeout=timeout)
    cache[vuln_id] = record if isinstance(record, dict) else None
    return cache[vuln_id]


def _finding_from_vuln(dep: Dependency, record: dict[str, Any]) -> Finding:
    """Build a :class:`Finding` from a dependency and an OSV vulnerability record."""
    vuln_id = record.get("id") if isinstance(record.get("id"), str) else ""

    aliases = tuple(a for a in record.get("aliases", []) if isinstance(a, str))

    summary = record.get("summary")
    if not isinstance(summary, str):
        details = record.get("details")
        summary = details if isinstance(details, str) else ""
    summary = summary.strip().replace("\n", " ")
    if len(summary) > _SUMMARY_MAX:
        summary = summary[: _SUMMARY_MAX - 3].rstrip() + "..."

    return Finding(
        dependency=dep,
        vuln_id=vuln_id,
        aliases=aliases,
        summary=summary,
        severity=_severity_from_record(record),
        url=_reference_url(record, vuln_id),
    )


def _severity_from_record(record: dict[str, Any]) -> str:
    """Best-effort severity band from an OSV record.

    Prefers explicit ``database_specific``/``ecosystem_specific`` severity strings, then
    falls back to parsing a CVSS v3 base score from the ``severity`` array. Returns
    ``"UNKNOWN"`` when nothing usable is present.
    """
    labelled = _labelled_severity(record.get("database_specific"))
    if labelled:
        return labelled

    for affected in record.get("affected", []):
        if isinstance(affected, dict):
            labelled = _labelled_severity(affected.get("ecosystem_specific"))
            if labelled:
                return labelled

    return _severity_from_cvss(record.get("severity"))


def _labelled_severity(container: Any) -> str | None:
    """Read a normalized severity label from a ``*_specific`` mapping, if present."""
    if not isinstance(container, dict):
        return None
    label = container.get("severity")
    if not isinstance(label, str):
        return None
    label = label.strip().upper()
    if label == "MEDIUM":
        label = "MODERATE"
    return label if label in _SEVERITY_RANK else None


def _severity_from_cvss(severity: Any) -> str:
    """Map the highest CVSS v3 base score in an OSV ``severity`` array to a band."""
    best = -1.0
    if isinstance(severity, list):
        for entry in severity:
            if not isinstance(entry, dict) or not isinstance(entry.get("score"), str):
                continue
            score = _cvss_base_score(entry["score"])
            if score is not None:
                best = max(best, score)
    if best < 0:
        return "UNKNOWN"
    if best >= 9.0:
        return "CRITICAL"
    if best >= 7.0:
        return "HIGH"
    if best >= 4.0:
        return "MODERATE"
    return "LOW"


def _cvss_base_score(vector: str) -> float | None:
    """OSV stores CVSS vectors, not numeric scores; we only need a coarse band.

    Rather than reimplement the CVSS formula (and pull the risk of getting it wrong),
    map the vector's own severity-bearing metrics conservatively: any vector at all is
    treated as at least MODERATE unless it looks clearly low-impact. This keeps banding
    dependency-free while erring toward surfacing, not hiding, findings.
    """
    vector = vector.strip().upper()
    if not vector.startswith("CVSS:3"):
        return None
    metrics = dict(part.split(":", 1) for part in vector.split("/")[1:] if ":" in part)
    # High-privilege/impact combinations -> treat as HIGH band; otherwise MODERATE.
    high_impact = any(metrics.get(m) == "H" for m in ("C", "I", "A"))
    network = metrics.get("AV") == "N"
    if high_impact and network:
        return 8.0
    if high_impact:
        return 7.0
    return 5.0


def _reference_url(record: dict[str, Any], vuln_id: str) -> str:
    """Pick an advisory URL, preferring an ADVISORY reference, else the OSV page."""
    references = record.get("references")
    if isinstance(references, list):
        urls = [
            r["url"] for r in references if isinstance(r, dict) and isinstance(r.get("url"), str)
        ]
        advisories = [
            r["url"]
            for r in references
            if isinstance(r, dict) and r.get("type") == "ADVISORY" and isinstance(r.get("url"), str)
        ]
        if advisories:
            return advisories[0]
        if urls:
            return urls[0]
    return f"https://osv.dev/vulnerability/{vuln_id}" if vuln_id else "https://osv.dev"

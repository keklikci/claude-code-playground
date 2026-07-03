"""MCP server exposing depaudit's scan/audit as tools.

Wraps the same orchestration the CLI uses (:func:`depaudit.parsers.load_dependencies`,
:func:`depaudit.osv.scan_dependencies`, :func:`depaudit.checks.run_all`) behind a
`FastMCP <https://github.com/modelcontextprotocol/python-sdk>`_ server, so any MCP-aware
client can audit a Python project's dependencies.

This module is **optional**: it is the only place in the package that imports ``mcp`` and is
never imported by the core CLI. Install it with ``pip install "depaudit[mcp]"`` and run the
server over stdio via the ``depaudit-mcp`` console script (or ``python -m depaudit.mcp_server``).

Security note (Module 6 framing): an MCP tool's arguments and, symmetrically, its *results* are
untrusted. The ``path`` argument here is an attacker-influenceable local file path and the file's
contents are treated as untrusted by the parsers (they parse text only — no ``eval``, no ``-r``
following). The server performs no network I/O except OSV.dev lookups, which go through
:mod:`depaudit.net` with an explicit timeout. A client consuming these results should likewise
treat them as data, not instructions.
"""

from __future__ import annotations

from typing import Any

from mcp.server.fastmcp import FastMCP

from depaudit import checks, net, osv, parsers
from depaudit.models import Dependency, Finding, Issue

mcp = FastMCP("depaudit")


def _dependency_dict(dep: Dependency) -> dict[str, Any]:
    """Serialize a :class:`~depaudit.models.Dependency` to a JSON-safe dict."""
    return {
        "name": dep.name,
        "version": dep.version,
        "specifier": dep.specifier,
        "source": dep.source,
    }


def _finding_dict(finding: Finding) -> dict[str, Any]:
    """Serialize a :class:`~depaudit.models.Finding` to a JSON-safe dict."""
    return {
        "dependency": _dependency_dict(finding.dependency),
        "vuln_id": finding.vuln_id,
        "aliases": list(finding.aliases),
        "summary": finding.summary,
        "severity": finding.severity,
        "url": finding.url,
    }


def _issue_dict(issue: Issue) -> dict[str, Any]:
    """Serialize an :class:`~depaudit.models.Issue` to a JSON-safe dict."""
    return {
        "dependency": _dependency_dict(issue.dependency),
        "check": issue.check,
        "severity": issue.severity,
        "message": issue.message,
    }


def run_scan(path: str | None = None, *, env: bool = False) -> dict[str, Any]:
    """Load dependencies from a source and scan them for known vulnerabilities.

    MCP-agnostic core of the :func:`scan` tool; returns plain, JSON-serializable data.

    Args:
        path: Path to a ``requirements.txt``-style file or a ``pyproject.toml``. Ignored
            when ``env`` is true.
        env: Scan the active Python environment instead of a file.

    Returns:
        A mapping with ``dependency_count``, ``skipped`` (unpinned deps that can't be
        queried), and ``findings`` (a list of serialized findings, most-severe first). On a
        network failure the mapping instead carries a single ``error`` key.
    """
    try:
        deps = parsers.load_dependencies(path, env=env)
    except ValueError as exc:
        return {"error": str(exc)}

    skipped = sum(1 for d in deps if not d.version)
    try:
        findings = osv.scan_dependencies(deps)
    except net.NetworkError as exc:
        return {"error": f"could not reach OSV.dev: {exc}"}

    return {
        "dependency_count": len(deps),
        "skipped": skipped,
        "findings": [_finding_dict(f) for f in findings],
    }


def run_audit(path: str | None = None, *, env: bool = False) -> dict[str, Any]:
    """Scan for vulnerabilities *and* run all local/PyPI checks over a source.

    MCP-agnostic core of the :func:`audit` tool; returns plain, JSON-serializable data.

    Args:
        path: Path to a ``requirements.txt``-style file or a ``pyproject.toml``. Ignored
            when ``env`` is true.
        env: Audit the active Python environment instead of a file.

    Returns:
        The :func:`run_scan` mapping plus an ``issues`` list from the check registry. On a
        network failure the mapping instead carries a single ``error`` key (checks are not run).
    """
    result = run_scan(path, env=env)
    if "error" in result:
        return result

    # Re-load is cheap and keeps run_audit independent of run_scan's internals.
    deps = parsers.load_dependencies(path, env=env)
    result["issues"] = [_issue_dict(i) for i in checks.run_all(deps)]
    return result


@mcp.tool()
def scan(path: str | None = None, env: bool = False) -> dict[str, Any]:
    """Scan a Python project's dependencies for known vulnerabilities via OSV.dev.

    Args:
        path: Path to a requirements.txt-style file or a pyproject.toml to scan.
        env: Scan the active Python environment instead of a file.

    Returns:
        dependency_count, skipped (unpinned deps), and findings (most-severe first);
        or an error message if the source is invalid or OSV.dev is unreachable.
    """
    return run_scan(path, env=env)


@mcp.tool()
def audit(path: str | None = None, env: bool = False) -> dict[str, Any]:
    """Scan dependencies for vulnerabilities and run all supply-chain checks.

    Runs the OSV.dev scan plus every registered check (license, typosquat, ...).

    Args:
        path: Path to a requirements.txt-style file or a pyproject.toml to audit.
        env: Audit the active Python environment instead of a file.

    Returns:
        The scan result plus an issues list from the checks; or an error message if the
        source is invalid or OSV.dev is unreachable.
    """
    return run_audit(path, env=env)


def main() -> None:
    """Run the depaudit MCP server over stdio."""
    mcp.run()


if __name__ == "__main__":  # pragma: no cover
    main()

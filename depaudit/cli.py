"""Command-line interface for depaudit."""

from __future__ import annotations

import argparse
import sys
from collections.abc import Sequence
from pathlib import Path

from depaudit import checks, net, osv
from depaudit.models import Dependency, Finding, Issue
from depaudit.parsers import parse_environment, parse_pyproject, parse_requirements

# Severity ordering for check issues (adds INFO to the OSV bands); used to sort most-severe first.
_ISSUE_SEVERITY_RANK = {"CRITICAL": 0, "HIGH": 1, "MODERATE": 2, "LOW": 3, "INFO": 4}


def _format_table(deps: Sequence[Dependency]) -> str:
    """Render dependencies as a simple aligned text table."""
    if not deps:
        return "No dependencies found."
    name_w = max(len("NAME"), *(len(d.name) for d in deps))
    ver_w = max(len("VERSION"), *(len(d.version or "-") for d in deps))
    rows = [f"{'NAME':<{name_w}}  {'VERSION':<{ver_w}}  SOURCE"]
    rows += [f"{d.name:<{name_w}}  {(d.version or '-'):<{ver_w}}  {d.source}" for d in deps]
    rows.append(f"\n{len(deps)} dependencies")
    return "\n".join(rows)


def _format_findings(findings: Sequence[Finding], *, skipped: int = 0) -> str:
    """Render vulnerability findings as an aligned text table.

    Args:
        findings: Findings to display, already sorted by the caller.
        skipped: Count of unpinned dependencies that couldn't be queried.
    """
    if not findings:
        summary = "No known vulnerabilities found."
    else:
        sev_w = max(len("SEVERITY"), *(len(f.severity) for f in findings))
        pkg_w = max(len("PACKAGE"), *(len(f.dependency.name) for f in findings))
        ver_w = max(len("VERSION"), *(len(f.dependency.version or "-") for f in findings))
        vuln_w = max(len("VULN"), *(len(f.vuln_id) for f in findings))
        header = (
            f"{'SEVERITY':<{sev_w}}  {'PACKAGE':<{pkg_w}}  "
            f"{'VERSION':<{ver_w}}  {'VULN':<{vuln_w}}  SUMMARY"
        )
        rows = [header]
        rows += [
            f"{f.severity:<{sev_w}}  {f.dependency.name:<{pkg_w}}  "
            f"{(f.dependency.version or '-'):<{ver_w}}  {f.vuln_id:<{vuln_w}}  {f.summary}"
            for f in findings
        ]
        affected = len({f.dependency.name for f in findings})
        rows.append(f"\n{len(findings)} vulnerabilities across {affected} packages")
        summary = "\n".join(rows)

    if skipped:
        summary += f"\n({skipped} unpinned dependencies skipped - pin a version to scan them)"
    return summary


def _format_issues(issues: Sequence[Issue]) -> str:
    """Render check issues as an aligned text table, most-severe first."""
    if not issues:
        return "No issues found by checks."
    ordered = sorted(
        issues,
        key=lambda i: (_ISSUE_SEVERITY_RANK.get(i.severity, 5), i.check, i.dependency.name),
    )
    sev_w = max(len("SEVERITY"), *(len(i.severity) for i in ordered))
    pkg_w = max(len("PACKAGE"), *(len(i.dependency.name) for i in ordered))
    ver_w = max(len("VERSION"), *(len(i.dependency.version or "-") for i in ordered))
    chk_w = max(len("CHECK"), *(len(i.check) for i in ordered))
    header = (
        f"{'SEVERITY':<{sev_w}}  {'PACKAGE':<{pkg_w}}  "
        f"{'VERSION':<{ver_w}}  {'CHECK':<{chk_w}}  MESSAGE"
    )
    rows = [header]
    rows += [
        f"{i.severity:<{sev_w}}  {i.dependency.name:<{pkg_w}}  "
        f"{(i.dependency.version or '-'):<{ver_w}}  {i.check:<{chk_w}}  {i.message}"
        for i in ordered
    ]
    affected = len({i.dependency.name for i in ordered})
    rows.append(f"\n{len(ordered)} issues across {affected} packages")
    return "\n".join(rows)


def _run_checks(deps: Sequence[Dependency]) -> list[Issue]:
    """Run every registered check over ``deps`` and collect their issues.

    Checks are best-effort and never raise (see ``depaudit/checks/CLAUDE.md``), so results are
    simply concatenated in registry order; the formatter handles ordering for display.
    """
    issues: list[Issue] = []
    for check in checks.CHECKS.values():
        issues.extend(check(deps))
    return issues


def _load_deps(args: argparse.Namespace, parser: argparse.ArgumentParser) -> list[Dependency]:
    """Load dependencies from the environment or a file, per shared parse/scan args."""
    if args.env:
        return parse_environment()
    if args.path:
        if Path(args.path).name == "pyproject.toml":
            return parse_pyproject(args.path)
        return parse_requirements(args.path)
    parser.error("provide a requirements file path or use --env")


def _add_source_args(sub_parser: argparse.ArgumentParser) -> None:
    """Add the shared ``path`` / ``--env`` dependency-source arguments to a subparser."""
    sub_parser.add_argument(
        "path", nargs="?", help="Path to a requirements.txt-style file or a pyproject.toml."
    )
    sub_parser.add_argument(
        "--env",
        action="store_true",
        help="Read the active Python environment instead of a file.",
    )


def build_parser() -> argparse.ArgumentParser:
    """Construct the argument parser for the ``depaudit`` command."""
    parser = argparse.ArgumentParser(
        prog="depaudit",
        description="Audit Python dependencies for supply-chain risk.",
    )
    sub = parser.add_subparsers(dest="command", required=True)

    p_parse = sub.add_parser(
        "parse", help="List dependencies from a requirements file or the environment."
    )
    _add_source_args(p_parse)

    p_scan = sub.add_parser("scan", help="Scan dependencies for known vulnerabilities via OSV.dev.")
    _add_source_args(p_scan)

    p_audit = sub.add_parser(
        "audit", help="Run the OSV.dev scan and all checks (license, typosquat, ...)."
    )
    _add_source_args(p_audit)

    return parser


def main(argv: Sequence[str] | None = None) -> int:
    """Entry point. Returns a process exit code."""
    parser = build_parser()
    args = parser.parse_args(argv)

    if args.command == "parse":
        deps = _load_deps(args, parser)
        print(_format_table(deps))
        return 0

    if args.command == "scan":
        deps = _load_deps(args, parser)
        skipped = sum(1 for d in deps if not d.version)
        try:
            findings = osv.scan_dependencies(deps)
        except net.NetworkError as exc:
            print(f"depaudit: could not reach OSV.dev: {exc}", file=sys.stderr)
            return 1
        print(_format_findings(findings, skipped=skipped))
        return 0

    if args.command == "audit":
        deps = _load_deps(args, parser)
        skipped = sum(1 for d in deps if not d.version)
        try:
            findings = osv.scan_dependencies(deps)
        except net.NetworkError as exc:
            print(f"depaudit: could not reach OSV.dev: {exc}", file=sys.stderr)
            return 1
        issues = _run_checks(deps)
        print(_format_findings(findings, skipped=skipped))
        print()
        print(_format_issues(issues))
        return 0

    parser.error(f"unknown command: {args.command}")  # pragma: no cover
    return 2


if __name__ == "__main__":  # pragma: no cover
    raise SystemExit(main())

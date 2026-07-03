"""Tests for the command-line interface, focused on the scan command."""

from depaudit import cli, net
from depaudit.models import Dependency, Finding, Issue


def _write_reqs(tmp_path):
    req = tmp_path / "requirements.txt"
    req.write_text("requests==2.19.1\nflask\n", encoding="utf-8")
    return req


def test_scan_reports_findings_and_exits_zero(tmp_path, monkeypatch, capsys):
    dep = Dependency(
        name="requests", version="2.19.1", specifier="==2.19.1", source="requirements.txt"
    )
    finding = Finding(
        dependency=dep,
        vuln_id="PYSEC-2019-1",
        aliases=("CVE-2019-0001",),
        summary="creds leak",
        severity="HIGH",
        url="https://example.com/a",
    )
    monkeypatch.setattr(cli.osv, "scan_dependencies", lambda deps: [finding])

    code = cli.main(["scan", str(_write_reqs(tmp_path))])
    out = capsys.readouterr().out

    assert code == 0  # findings are reported, not gated (exit 0 by design)
    assert "PYSEC-2019-1" in out
    assert "HIGH" in out
    assert "1 vulnerabilities across 1 packages" in out
    # The unpinned "flask" line should be reported as skipped.
    assert "1 unpinned dependencies skipped" in out


def test_scan_clean_project_reports_none(tmp_path, monkeypatch, capsys):
    monkeypatch.setattr(cli.osv, "scan_dependencies", lambda deps: [])
    req = tmp_path / "requirements.txt"
    req.write_text("requests==2.19.1\n", encoding="utf-8")

    code = cli.main(["scan", str(req)])
    out = capsys.readouterr().out

    assert code == 0
    assert "No known vulnerabilities found." in out


def test_scan_network_error_exits_one(tmp_path, monkeypatch, capsys):
    def boom(deps):
        raise net.NetworkError("OSV.dev unreachable")

    monkeypatch.setattr(cli.osv, "scan_dependencies", boom)
    req = tmp_path / "requirements.txt"
    req.write_text("requests==2.19.1\n", encoding="utf-8")

    code = cli.main(["scan", str(req)])
    captured = capsys.readouterr()

    assert code == 1
    assert "could not reach OSV.dev" in captured.err


def test_audit_prints_findings_and_issues(tmp_path, monkeypatch, capsys):
    dep = Dependency(
        name="requests", version="2.19.1", specifier="==2.19.1", source="requirements.txt"
    )
    finding = Finding(
        dependency=dep,
        vuln_id="PYSEC-2019-1",
        aliases=("CVE-2019-0001",),
        summary="creds leak",
        severity="HIGH",
        url="https://example.com/a",
    )
    issue = Issue(
        dependency=dep,
        check="license",
        severity="MODERATE",
        message="GPL license - review redistribution terms",
    )
    monkeypatch.setattr(cli.osv, "scan_dependencies", lambda deps: [finding])
    # Isolate the CLI wiring from the real (network-backed) checks.
    monkeypatch.setattr(cli.checks, "CHECKS", {"license": lambda deps: [issue]})

    code = cli.main(["audit", str(_write_reqs(tmp_path))])
    out = capsys.readouterr().out

    assert code == 0
    # Findings section.
    assert "PYSEC-2019-1" in out
    assert "1 vulnerabilities across 1 packages" in out
    # Issues section.
    assert "license" in out
    assert "GPL license" in out
    assert "1 issues across 1 packages" in out


def test_audit_network_error_exits_one(tmp_path, monkeypatch, capsys):
    def boom(deps):
        raise net.NetworkError("OSV.dev unreachable")

    # Checks must not run if the OSV scan itself fails.
    def unexpected(deps):  # pragma: no cover - must not be reached
        raise AssertionError("checks should not run after an OSV network error")

    monkeypatch.setattr(cli.osv, "scan_dependencies", boom)
    monkeypatch.setattr(cli.checks, "CHECKS", {"license": unexpected})

    code = cli.main(["audit", str(_write_reqs(tmp_path))])
    captured = capsys.readouterr()

    assert code == 1
    assert "could not reach OSV.dev" in captured.err

"""Tests for the depaudit MCP server (depaudit.mcp_server).

Skipped entirely when the optional ``mcp`` dependency isn't installed, so the core test
suite still runs against a zero-dependency checkout.
"""

import asyncio
import json

import pytest

pytest.importorskip("mcp")

from depaudit import checks, mcp_server, net, osv  # noqa: E402
from depaudit.models import Dependency, Finding, Issue  # noqa: E402


def _dep(name, version):
    spec = f"=={version}" if version else ""
    return Dependency(name=name, version=version, specifier=spec, source="requirements.txt")


def _finding(dep):
    return Finding(
        dependency=dep,
        vuln_id="PYSEC-2019-1",
        aliases=("CVE-2019-0001",),
        summary="example vuln",
        severity="HIGH",
        url="https://example.com/advisory",
    )


def _structured(result):
    """Extract the structured dict from a FastMCP ``call_tool`` result, tolerating shapes.

    Recent FastMCP returns ``(content, structured)``; we also handle a bare dict or a list of
    content blocks whose text is JSON.
    """
    if isinstance(result, tuple):
        result = result[1]
    if isinstance(result, dict):
        return result
    return json.loads(result[0].text)


def test_scan_unpinned_makes_no_network(tmp_path, monkeypatch):
    req = tmp_path / "requirements.txt"
    req.write_text("flask\nrequests\n", encoding="utf-8")

    def _boom(*args, **kwargs):
        raise AssertionError("no network expected for unpinned-only deps")

    monkeypatch.setattr(osv.net, "request_json", _boom)

    result = mcp_server.run_scan(str(req))

    assert result["dependency_count"] == 2
    assert result["skipped"] == 2
    assert result["findings"] == []


def test_scan_serializes_findings(tmp_path, monkeypatch):
    req = tmp_path / "requirements.txt"
    req.write_text("requests==2.19.1\n", encoding="utf-8")
    monkeypatch.setattr(
        osv, "scan_dependencies", lambda deps: [_finding(_dep("requests", "2.19.1"))]
    )

    result = mcp_server.run_scan(str(req))

    assert result["skipped"] == 0
    assert len(result["findings"]) == 1
    finding = result["findings"][0]
    assert finding["vuln_id"] == "PYSEC-2019-1"
    assert finding["aliases"] == ["CVE-2019-0001"]
    assert finding["severity"] == "HIGH"
    assert finding["dependency"]["name"] == "requests"
    assert finding["dependency"]["version"] == "2.19.1"


def test_audit_includes_serialized_issues(tmp_path, monkeypatch):
    req = tmp_path / "requirements.txt"
    req.write_text("requests==2.19.1\n", encoding="utf-8")
    monkeypatch.setattr(osv, "scan_dependencies", lambda deps: [])
    issue = Issue(
        dependency=_dep("reqests", "1.0"),
        check="typosquat",
        severity="MODERATE",
        message="looks like 'requests'",
    )
    monkeypatch.setattr(checks, "run_all", lambda deps: [issue])

    result = mcp_server.run_audit(str(req))

    assert result["findings"] == []
    assert len(result["issues"]) == 1
    assert result["issues"][0]["check"] == "typosquat"
    assert result["issues"][0]["dependency"]["name"] == "reqests"


def test_scan_network_error_returns_error_dict(tmp_path, monkeypatch):
    req = tmp_path / "requirements.txt"
    req.write_text("requests==2.19.1\n", encoding="utf-8")

    def _raise(deps):
        raise net.NetworkError("boom")

    monkeypatch.setattr(osv, "scan_dependencies", _raise)

    result = mcp_server.run_scan(str(req))

    assert "error" in result
    assert "OSV.dev" in result["error"]
    assert "findings" not in result


def test_invalid_source_returns_error_dict():
    result = mcp_server.run_scan(path=None, env=False)

    assert "error" in result
    assert "findings" not in result


def test_tools_registered_and_callable(tmp_path, monkeypatch):
    req = tmp_path / "requirements.txt"
    req.write_text("requests==2.19.1\n", encoding="utf-8")
    monkeypatch.setattr(
        osv, "scan_dependencies", lambda deps: [_finding(_dep("requests", "2.19.1"))]
    )

    tools = asyncio.run(mcp_server.mcp.list_tools())
    assert {"scan", "audit"} <= {t.name for t in tools}

    raw = asyncio.run(mcp_server.mcp.call_tool("scan", {"path": str(req)}))
    structured = _structured(raw)
    assert structured["dependency_count"] == 1
    assert structured["findings"][0]["vuln_id"] == "PYSEC-2019-1"

"""Tests for the OSV.dev vulnerability engine (depaudit.osv)."""

from depaudit import osv
from depaudit.models import Dependency


def _dep(name, version):
    spec = f"=={version}" if version else ""
    return Dependency(name=name, version=version, specifier=spec, source="requirements.txt")


def _fake_osv(querybatch_results, vuln_records):
    """Build a request_json stand-in dispatching on the OSV endpoint in the URL."""

    def request_json(url, *, method="GET", payload=None, timeout=osv.net.DEFAULT_TIMEOUT):
        if url.endswith("/querybatch"):
            return {"results": querybatch_results}
        vuln_id = url.rsplit("/", 1)[-1]
        return vuln_records[vuln_id]

    return request_json


def test_scan_builds_findings_for_known_vuln(monkeypatch):
    querybatch = [{"vulns": [{"id": "PYSEC-2019-1"}]}]
    records = {
        "PYSEC-2019-1": {
            "id": "PYSEC-2019-1",
            "summary": "requests leaks credentials",
            "aliases": ["CVE-2019-0001"],
            "database_specific": {"severity": "HIGH"},
            "references": [{"type": "ADVISORY", "url": "https://example.com/advisory"}],
        }
    }
    monkeypatch.setattr(osv.net, "request_json", _fake_osv(querybatch, records))

    findings = osv.scan_dependencies([_dep("requests", "2.19.1")])

    assert len(findings) == 1
    f = findings[0]
    assert f.dependency.name == "requests"
    assert f.vuln_id == "PYSEC-2019-1"
    assert f.aliases == ("CVE-2019-0001",)
    assert f.severity == "HIGH"
    assert f.url == "https://example.com/advisory"


def test_scan_skips_unpinned_dependencies(monkeypatch):
    calls = {"n": 0}

    def tracking(url, *, method="GET", payload=None, timeout=osv.net.DEFAULT_TIMEOUT):
        calls["n"] += 1
        return {"results": []}

    monkeypatch.setattr(osv.net, "request_json", tracking)

    # An unpinned dep alone -> nothing queryable, so no request is made at all.
    assert osv.scan_dependencies([_dep("flask", None)]) == []
    assert calls["n"] == 0


def test_scan_clean_dependency_returns_no_findings(monkeypatch):
    monkeypatch.setattr(osv.net, "request_json", _fake_osv([{"vulns": []}], {}))
    assert osv.scan_dependencies([_dep("requests", "9.9.9")]) == []


def test_scan_tolerates_malformed_osv_response(monkeypatch):
    # results not a list, a non-dict result, vulns missing ids — none should raise.
    querybatch = ["garbage", {"vulns": [{"no_id": True}, 123]}]
    monkeypatch.setattr(osv.net, "request_json", _fake_osv(querybatch, {}))

    findings = osv.scan_dependencies([_dep("a", "1.0"), _dep("b", "2.0")])
    assert findings == []


def test_scan_deduplicates_shared_vuln_fetch(monkeypatch):
    querybatch = [
        {"vulns": [{"id": "SHARED-1"}]},
        {"vulns": [{"id": "SHARED-1"}]},
    ]
    records = {"SHARED-1": {"id": "SHARED-1", "summary": "shared"}}
    fetches = {"n": 0}

    def counting(url, *, method="GET", payload=None, timeout=osv.net.DEFAULT_TIMEOUT):
        if url.endswith("/querybatch"):
            return {"results": querybatch}
        fetches["n"] += 1
        return records[url.rsplit("/", 1)[-1]]

    monkeypatch.setattr(osv.net, "request_json", counting)

    findings = osv.scan_dependencies([_dep("a", "1.0"), _dep("b", "2.0")])
    assert len(findings) == 2  # one finding per affected dep
    assert fetches["n"] == 1  # but the shared vuln is fetched only once


def test_severity_variants(monkeypatch):
    # ecosystem_specific severity, MEDIUM -> MODERATE normalization, and UNKNOWN fallback.
    records = {
        "ECO-1": {"id": "ECO-1", "affected": [{"ecosystem_specific": {"severity": "MEDIUM"}}]},
        "NONE-1": {"id": "NONE-1"},
    }
    querybatch = [{"vulns": [{"id": "ECO-1"}, {"id": "NONE-1"}]}]
    monkeypatch.setattr(osv.net, "request_json", _fake_osv(querybatch, records))

    by_id = {f.vuln_id: f for f in osv.scan_dependencies([_dep("pkg", "1.0")])}
    assert by_id["ECO-1"].severity == "MODERATE"
    assert by_id["NONE-1"].severity == "UNKNOWN"


def test_severity_from_cvss_vector(monkeypatch):
    records = {
        "CVSS-1": {
            "id": "CVSS-1",
            "severity": [
                {"type": "CVSS_V3", "score": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"}
            ],
        }
    }
    querybatch = [{"vulns": [{"id": "CVSS-1"}]}]
    monkeypatch.setattr(osv.net, "request_json", _fake_osv(querybatch, records))

    (finding,) = osv.scan_dependencies([_dep("pkg", "1.0")])
    assert finding.severity == "HIGH"


def test_findings_sorted_most_severe_first(monkeypatch):
    querybatch = [{"vulns": [{"id": "LOW-1"}, {"id": "CRIT-1"}]}]
    records = {
        "LOW-1": {"id": "LOW-1", "database_specific": {"severity": "LOW"}},
        "CRIT-1": {"id": "CRIT-1", "database_specific": {"severity": "CRITICAL"}},
    }
    monkeypatch.setattr(osv.net, "request_json", _fake_osv(querybatch, records))

    severities = [f.severity for f in osv.scan_dependencies([_dep("pkg", "1.0")])]
    assert severities == ["CRITICAL", "LOW"]

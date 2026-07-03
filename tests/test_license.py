"""Tests for the license check (depaudit.checks.license)."""

import pytest

from depaudit import net
from depaudit.checks.license import run
from depaudit.models import Dependency


def _dep(name, version="1.0.0"):
    return Dependency(name=name, version=version, specifier="", source="test")


def _fake_pypi(info_by_name):
    """A request_json stand-in returning canned PyPI ``info`` keyed by the name in the URL."""

    def request_json(url, *, method="GET", payload=None, timeout=net.DEFAULT_TIMEOUT):
        name = url.rsplit("/pypi/", 1)[-1].rsplit("/json", 1)[0]
        return {"info": info_by_name[name]}

    return request_json


def test_permissive_license_produces_no_issue(monkeypatch):
    monkeypatch.setattr(net, "request_json", _fake_pypi({"requests": {"license": "MIT"}}))
    assert run([_dep("requests")]) == []


def test_permissive_from_classifiers_produces_no_issue(monkeypatch):
    info = {"license": "", "classifiers": ["License :: OSI Approved :: BSD License"]}
    monkeypatch.setattr(net, "request_json", _fake_pypi({"numpy": info}))
    assert run([_dep("numpy")]) == []


def test_missing_license_is_flagged_low(monkeypatch):
    info = {"license": "", "classifiers": ["Programming Language :: Python :: 3"]}
    monkeypatch.setattr(net, "request_json", _fake_pypi({"mystery": info}))

    issues = run([_dep("mystery")])

    assert len(issues) == 1
    assert issues[0].check == "license"
    assert issues[0].severity == "LOW"
    assert "no license metadata" in issues[0].message


def test_copyleft_license_field_is_flagged_moderate(monkeypatch):
    monkeypatch.setattr(net, "request_json", _fake_pypi({"copyleftpkg": {"license": "GPLv3"}}))

    issues = run([_dep("copyleftpkg")])

    assert len(issues) == 1
    assert issues[0].severity == "MODERATE"
    assert "GPL" in issues[0].message


def test_copyleft_from_classifier_is_flagged_moderate(monkeypatch):
    info = {
        "license": "",
        "classifiers": ["License :: OSI Approved :: GNU Affero General Public License v3 (AGPL)"],
    }
    monkeypatch.setattr(net, "request_json", _fake_pypi({"agplpkg": info}))

    issues = run([_dep("agplpkg")])

    assert len(issues) == 1
    assert issues[0].severity == "MODERATE"
    assert "AGPL" in issues[0].message


def test_network_error_skips_dependency(monkeypatch):
    def boom(url, *, method="GET", payload=None, timeout=net.DEFAULT_TIMEOUT):
        raise net.NetworkError("pypi unreachable")

    monkeypatch.setattr(net, "request_json", boom)
    # A network failure for the one dep must be swallowed, not raised.
    assert run([_dep("requests")]) == []


@pytest.mark.parametrize("payload", [None, [], {"info": "not-a-dict"}, {}])
def test_malformed_response_skips_dependency(monkeypatch, payload):
    monkeypatch.setattr(net, "request_json", lambda url, **kw: payload)
    assert run([_dep("requests")]) == []


def test_license_handles_odd_input(monkeypatch):
    # Empty list and an empty name must be skipped, never raised on — and no network call.
    def unexpected(url, **kw):  # pragma: no cover - must not be reached
        raise AssertionError("network should not be called for empty input")

    monkeypatch.setattr(net, "request_json", unexpected)
    assert run([]) == []
    assert run([_dep("", version=None)]) == []

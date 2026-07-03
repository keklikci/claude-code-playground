"""Tests for the license check."""

from depaudit.checks.license import run
from depaudit.models import Dependency


def _dep(name, version="1.0.0"):
    return Dependency(name=name, version=version, specifier="", source="test")


def test_license_issues_are_tagged():
    # Every Issue this check emits must carry its own name.
    issues = run([_dep("example")])
    assert all(i.check == "license" for i in issues)


def test_license_handles_odd_input():
    # Empty and unusual input must be skipped, never raised on.
    assert run([]) == []
    assert run([_dep("", version=None)]) == []

"""Tests for the typosquat check (depaudit.checks.typosquat)."""

from depaudit.checks.typosquat import _within_distance_one, run
from depaudit.models import Dependency


def _dep(name, version="1.0.0"):
    return Dependency(name=name, version=version, specifier="", source="test")


def test_exact_popular_name_is_not_flagged():
    # A dependency that IS the popular package must never be flagged.
    assert run([_dep("requests"), _dep("numpy")]) == []


def test_near_miss_is_flagged_moderate():
    issues = run([_dep("requsts")])  # one deletion away from "requests"

    assert len(issues) == 1
    assert issues[0].check == "typosquat"
    assert issues[0].severity == "MODERATE"
    assert "requests" in issues[0].message


def test_substitution_near_miss_is_flagged():
    # "flazk" -> "flask" is a single substitution.
    (issue,) = run([_dep("flazk")])
    assert "flask" in issue.message


def test_unrelated_name_is_not_flagged():
    assert run([_dep("my-internal-service-client")]) == []


def test_distance_two_is_not_flagged():
    # "reqessts" is two edits from "requests"; below the flag threshold.
    assert run([_dep("reqessts")]) == []


def test_handles_odd_input():
    # Empty list and malformed names must be skipped, never raised on.
    assert run([]) == []
    assert run([_dep("", version=None)]) == []


def test_within_distance_one_cases():
    assert _within_distance_one("requests", "requests") is True  # identical
    assert _within_distance_one("requsts", "requests") is True  # deletion
    assert _within_distance_one("requestss", "requests") is True  # insertion
    assert _within_distance_one("reguests", "requests") is True  # substitution
    assert _within_distance_one("reqessts", "requests") is False  # distance 2
    assert _within_distance_one("abc", "abcde") is False  # length gap > 1

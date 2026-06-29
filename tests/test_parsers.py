"""Tests for dependency parsing."""

from depaudit.parsers import normalize_name, parse_environment, parse_requirements


def test_normalize_name():
    assert normalize_name("Flask_Login") == "flask-login"
    assert normalize_name("My.Package") == "my-package"
    assert normalize_name("ruamel.yaml") == "ruamel-yaml"


def test_parse_requirements_basic(tmp_path):
    req = tmp_path / "requirements.txt"
    req.write_text(
        "\n".join(
            [
                "# a comment",
                "",
                "requests==2.19.1",
                "Flask>=2.0,<3  # web framework",
                "urllib3==1.24.1 ; python_version < '3.11'",
                "-r other.txt",
                "-e .",
                "git+https://example.com/pkg.git",
                "package[extra]==1.0.0",
            ]
        ),
        encoding="utf-8",
    )

    by_name = {d.name: d for d in parse_requirements(req)}

    # Options, comments, and URLs are skipped; four real requirements remain.
    assert set(by_name) == {"requests", "flask", "urllib3", "package"}

    assert by_name["requests"].version == "2.19.1"
    assert by_name["requests"].source == "requirements.txt"

    # Range specifier -> no concrete version, but the specifier is preserved.
    assert by_name["flask"].version is None
    assert by_name["flask"].specifier.startswith(">=2.0")

    # Environment marker is stripped, leaving the pin.
    assert by_name["urllib3"].version == "1.24.1"

    # Extras are ignored for the name; the pin is still captured.
    assert by_name["package"].version == "1.0.0"


def test_parse_environment_is_well_formed():
    deps = parse_environment()
    names = {d.name for d in deps}

    # pip is present in essentially every working environment.
    assert "pip" in names
    assert all(d.source == "environment" for d in deps)
    # Results are sorted by normalized name.
    assert [d.name for d in deps] == sorted(names)

"""Tests for the pyproject.toml parser."""

from depaudit.parsers import parse_pyproject


def test_parse_pyproject_basic(tmp_path):
    pp = tmp_path / "pyproject.toml"
    pp.write_text(
        "\n".join(
            [
                "[project]",
                'name = "demo"',
                "dependencies = [",
                '    "requests==2.19.1",',
                '    "Flask>=2.0,<3",',
                "    \"urllib3==1.24.1 ; python_version < '3.11'\",",
                '    "package[extra]==1.0.0",',
                "]",
                "",
                "[project.optional-dependencies]",
                'dev = ["pytest>=8"]',
                'docs = ["sphinx==7.2.6"]',
            ]
        ),
        encoding="utf-8",
    )

    deps = parse_pyproject(pp)
    by_name = {d.name: d for d in deps}

    # Runtime deps plus both optional groups are collected.
    assert set(by_name) == {"requests", "flask", "urllib3", "package", "pytest", "sphinx"}

    assert by_name["requests"].version == "2.19.1"
    assert by_name["requests"].source == "pyproject.toml"

    # Range specifier -> no concrete version, but the specifier is preserved.
    assert by_name["flask"].version is None
    assert by_name["flask"].specifier.startswith(">=2.0")

    # Environment marker stripped, leaving the pin; extras ignored for the name.
    assert by_name["urllib3"].version == "1.24.1"
    assert by_name["package"].version == "1.0.0"

    # Pulled from an optional-dependencies group.
    assert by_name["sphinx"].version == "7.2.6"


def test_parse_pyproject_no_project_table(tmp_path):
    pp = tmp_path / "pyproject.toml"
    pp.write_text('[build-system]\nrequires = ["setuptools>=68"]\n', encoding="utf-8")
    assert parse_pyproject(pp) == []


def test_parse_pyproject_malformed_toml_does_not_raise(tmp_path):
    pp = tmp_path / "pyproject.toml"
    # Unterminated array / stray bracket: invalid TOML.
    pp.write_text('[project]\ndependencies = ["requests"\n', encoding="utf-8")
    assert parse_pyproject(pp) == []


def test_parse_pyproject_skips_non_string_entries(tmp_path):
    pp = tmp_path / "pyproject.toml"
    pp.write_text(
        "\n".join(
            [
                "[project]",
                "dependencies = [",
                '    "requests==2.19.1",',
                "    123,",
                "]",
            ]
        ),
        encoding="utf-8",
    )
    deps = parse_pyproject(pp)
    assert [d.name for d in deps] == ["requests"]

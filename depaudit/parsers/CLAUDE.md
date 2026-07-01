# Parsers — local rules

These rules **add to** the root `CLAUDE.md`; they apply when working in `depaudit/parsers/`.

A parser turns some dependency source (a requirements file, the environment, later a
`pyproject.toml` / lockfile) into a `list[Dependency]` (see `depaudit/models.py`).

## Rules

- **Best‑effort and conservative:** never crash on malformed input. Skip lines/entries you can't
  parse rather than raising (see `parse_requirements` in `requirements.py`).
- **Pure:** parsers only read local files or the installed environment. **No network, no writes,
  no side effects.** (Network belongs in `depaudit/net.py`, Module 3+.)
- **Normalize every name** through `normalize_name` (PEP 503) before constructing a `Dependency`.
  It lives in `_normalize.py` and is shared by all parsers.
- **Untrusted input:** a `requirements.txt` (or lockfile) is attacker‑controllable data. Don't
  `eval`, don't execute it, don't follow `-r`/`-e`/URL directives — parse text only.
- Keep regexes **anchored and commented**, mirroring `requirements.py`.

## Adding a new parser

1. New submodule `depaudit/parsers/<source>.py` exposing `parse_<source>(...) -> list[Dependency]`.
2. Re‑export it from `__init__.py` and add it to `__all__` so callers use
   `from depaudit.parsers import parse_<source>`.
3. Add `tests/test_<source>.py` with a `tmp_path` fixture and **at least one malformed‑input
   case** proving it skips rather than raises.

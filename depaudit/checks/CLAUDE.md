# Checks — local rules

These rules **add to** the root `CLAUDE.md`; they apply when working in `depaudit/checks/`.

A *check* inspects the project's dependencies and reports supply-chain problems. Each check
turns a `Sequence[Dependency]` into a `list[Issue]` (see `depaudit/models.py`). The
`/add-scanner` skill scaffolds new checks that follow this contract.

## The contract

- A check lives in `depaudit/checks/<name>.py` and exposes:
  ```python
  def run(deps: Sequence[Dependency]) -> list[Issue]: ...
  ```
- It registers itself in `depaudit/checks/__init__.py` by adding to the `CHECKS` dict
  (`CHECKS["<name>"] = run`) so a future `scan` can iterate every check by name.
- Return `Issue` records (`depaudit/models.py`): `dependency`, `check` (the check's name),
  `severity` (`CRITICAL`/`HIGH`/`MODERATE`/`LOW`/`INFO`), and a human-readable `message`.

## Rules

- **Best-effort and conservative:** never crash on odd input — skip what you can't evaluate
  rather than raising (mirrors the parsers in `depaudit/parsers/`).
- **Local by default, network only via `net.py`:** a check that needs the network (e.g. PyPI
  metadata) must go through `depaudit/net.py` with an explicit timeout — never call
  `urllib`/`requests` directly (see `depaudit/osv.py` for the pattern). Pure-local checks
  (e.g. license/typosquat against a bundled list) do no I/O at all.
- **Untrusted input:** dependency names/versions and any fetched metadata are
  attacker-controllable. Validate with `isinstance`/guards; don't `eval`/`exec`.
- Full type hints + Google-style docstrings; start the module with
  `from __future__ import annotations`.

## Adding a new check (what `/add-scanner` does)

1. New module `depaudit/checks/<name>.py` exposing `run(deps) -> list[Issue]`.
2. Register it: `CHECKS["<name>"] = run` in `__init__.py` (and re-export if useful).
3. Add `tests/test_<name>.py` constructing `Dependency` values directly (or `tmp_path` for
   file-based checks), with **at least one edge/malformed case** proving it skips, not raises.
4. Leave CLI wiring to the module that integrates the check surface (Module 5+).

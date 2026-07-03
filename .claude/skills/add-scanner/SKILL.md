---
name: add-scanner
description: Scaffold a new depaudit check (a "scanner") — creates depaudit/checks/<name>.py exposing run(deps)->list[Issue], registers it in the CHECKS registry, and adds tests/test_<name>.py, all following project conventions. Use when the user asks to add a new check/scanner/detector to depaudit (e.g. typosquatting, license, integrity, maintainer-age), or invokes /add-scanner. Pass the check name as the argument.
---

# add-scanner

Scaffold a new dependency **check** for `depaudit`, following the contract in
`depaudit/checks/CLAUDE.md`. The check name comes from the skill argument (e.g.
`/add-scanner typosquat`); if none was given, ask the user for one.

## Steps

1. **Resolve the name.** Take the argument, lowercase it, and turn separators into
   underscores for the module (`license`, `typosquat`, `maintainer_age`). Use the same
   value as the registry key and the `check` field on emitted `Issue`s.

2. **Read the conventions first:** `depaudit/checks/CLAUDE.md` (the check contract) and the
   root `CLAUDE.md` (security + code rules). Match them exactly.

3. **Create `depaudit/checks/<name>.py`** from this template. Keep it pure/local unless the
   check truly needs the network — if it does, route through `depaudit.net` with an explicit
   timeout (see `depaudit/osv.py`), never `urllib`/`requests` directly.

   ```python
   """<One-line description of what this check flags>."""

   from __future__ import annotations

   from collections.abc import Sequence

   from depaudit.models import Dependency, Issue

   CHECK_NAME = "<name>"


   def run(deps: Sequence[Dependency]) -> list[Issue]:
       """<What the check does and when it flags an Issue>.

       Best-effort: dependencies it can't evaluate are skipped, never raised on.

       Args:
           deps: The dependencies to inspect.

       Returns:
           One :class:`~depaudit.models.Issue` per problem found (empty if none).
       """
       issues: list[Issue] = []
       for dep in deps:
           # TODO: implement the check. Treat dep.name / dep.version as untrusted.
           _ = dep
       return issues
   ```

4. **Register it** in `depaudit/checks/__init__.py`:
   - add `from depaudit.checks.<name> import run as _<name>_run`
   - add `CHECKS["<name>"] = _<name>_run`
   Keep imports sorted (ruff `I` will fix ordering with `ruff check --fix`).

5. **Create `tests/test_<name>.py`** from this template — construct `Dependency` directly
   (use `tmp_path` only if the check reads files), and include **at least one edge/malformed
   case** per the contract:

   ```python
   """Tests for the <name> check."""

   from depaudit.checks.<name> import run
   from depaudit.models import Dependency


   def _dep(name, version="1.0.0"):
       return Dependency(name=name, version=version, specifier="", source="test")


   def test_<name>_flags_expected():
       issues = run([_dep("example")])
       # TODO: assert on the Issue(s) the check should produce.
       assert all(i.check == "<name>" for i in issues)


   def test_<name>_handles_odd_input():
       # Empty / unusual input must not raise.
       assert run([]) == []
       assert run([_dep("", version=None)]) == []
   ```

6. **Verify:** run `pytest`, then `ruff check .` (add `--fix` for import order) and
   `ruff format .`. All must be green before finishing.

7. **Do not touch `cli.py`.** Wiring the check surface into the CLI belongs to the module that
   integrates checks (Module 5+). Finish by reminding the user the check is scaffolded and
   registered in `CHECKS`, and point at where to implement the real logic and assertions.

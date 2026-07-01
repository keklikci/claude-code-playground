# claude-code-playground

This repo is a hands‑on learning environment for mastering Claude Code, anchored by a capstone
security tool — `depaudit`, a Python dependency / supply‑chain scanner built module by module.

## Learning roadmap

The full multi‑session curriculum lives at **[docs/claude-code-mastery.md](docs/claude-code-mastery.md)**.
When resuming, the user will say *"We're resuming the Claude Code mastery roadmap. I'm on Module N."*
Pick up at that module; don't skip its **Mastery check** before advancing.

---

## depaudit

Audits a Python project's dependencies for supply‑chain risk. Today it **parses** dependencies
(from `requirements.txt` files or the active environment). The CVE/vulnerability engine and
`net.py` arrive in Module 3.

### Commands

```sh
python -m pip install -e ".[dev]"   # dev install (from an activated .venv)
pytest                              # run tests
ruff check .                        # lint
ruff format .                       # format (don't hand-align code)
depaudit parse requirements.txt     # list deps declared in a file
depaudit parse --env                # list deps in the active environment
```

Tests and `ruff` are pre‑allowed in `.claude/settings.json`; network commands prompt.

### Layout

- `depaudit/` — package: `cli.py` (argparse entry point), `models.py` (`Dependency`),
  `parsers/` (dependency parsers; see its own `CLAUDE.md`).
- `tests/` — pytest suite. `examples/` — sample inputs. `docs/` — the roadmap.

### Code conventions

- Target **Python ≥ 3.10**. Start every module with `from __future__ import annotations`.
- Full type hints on public functions. Data models are **frozen, `slots=True` dataclasses**
  (see `depaudit/models.py`).
- **Google‑style docstrings** on public functions/classes.
- `ruff`: `line-length = 100`, target `py310`, lint set `E, F, I, B, UP, S, BLE`. Let
  `ruff format` handle layout; let `ruff --fix` sort imports (`I`).

### Test conventions

- `pytest`, `testpaths = ["tests"]`. One `test_<module>.py` per module.
- Use the `tmp_path` fixture for filesystem tests; cover malformed / edge input, not just the
  happy path. `assert` is fine in tests (`S101` is ignored there).

### Security coding rules (this project's focus)

- **Minimize attack surface:** runtime dependencies stay at **zero** unless a new one is
  justified on security grounds. Every dependency is attack surface.
- **No bare/blind `except`** — always catch specific exceptions (enforced by ruff `BLE`).
- **All network I/O goes through `depaudit/net.py`** (Module 3+) with explicit **timeouts** and
  retries. Never call `requests`/`urllib` directly from feature code. This applies to every
  OSV.dev API call — always pass an explicit timeout; never rely on library defaults.
- **Treat all external input as untrusted:** requirements files, environment metadata, OSV/API
  responses, and (later) MCP tool output.
- Don't blanket‑ignore `S`/`B` lints — fix them, or use a narrow `# noqa: <code>` with a reason.

### Git / workflow

General commit / branch / PR conventions (Conventional Commits, one branch & PR per unit of
work, required PR metadata, and the PR description structure) live in my user
`~/.claude/CLAUDE.md`. Project-specific bindings:

- **PR titles**: `Module N: text` (e.g. `Module 2: instructions & memory + pyproject parser`).
- **GitHub Project**: `depaudit — supply-chain scanner` (user project #3).

### Memory notes

- Keep this file lean — reference code for detail instead of restating it; don't dump code
  structure or git history here.
- Parser‑specific rules live in `depaudit/parsers/CLAUDE.md` (nested memory, loaded when working
  in that directory).

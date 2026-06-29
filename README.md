# claude-code-playground

A hands‑on environment for mastering Claude Code, anchored by a capstone security tool:
**`depaudit`** — a Python dependency / supply‑chain scanner built module by module.
See the [mastery roadmap](docs/claude-code-mastery.md).

---

## depaudit

Audit a Python project's dependencies for supply‑chain risk: known CVEs, typosquatting,
license compliance, and package integrity.

### Status

Module 1 — dependency parsing. `depaudit` can list the dependencies declared in a
`requirements.txt` file or installed in the active Python environment.

### Install (development)

```sh
python -m venv .venv
.venv\Scripts\python -m pip install -e ".[dev]"        # Windows
# source .venv/bin/activate && pip install -e ".[dev]"  # macOS/Linux
```

### Usage

```sh
depaudit parse requirements.txt   # list deps declared in a file
depaudit parse --env              # list deps installed in the current environment
```

### Develop

```sh
pytest        # run tests
ruff check .  # lint
```

# claude-code-playground

A hands‑on environment for mastering Claude Code, anchored by a capstone security tool:
**`depaudit`** — a Python dependency / supply‑chain scanner built module by module.
See the [mastery roadmap](docs/claude-code-mastery.md).

---

## depaudit

Audit a Python project's dependencies for supply‑chain risk: known CVEs, typosquatting,
license compliance, and package integrity.

### Status

Through Module 6. `depaudit` parses dependencies (requirements files, `pyproject.toml`, or the
active environment), scans them for known vulnerabilities via OSV.dev, runs local/PyPI checks
(license, typosquat), and exposes `scan`/`audit` as **MCP tools** (`depaudit-mcp`).

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
depaudit scan requirements.txt    # scan deps for known vulnerabilities (OSV.dev)
depaudit audit requirements.txt   # scan + run all checks (license, typosquat, ...)
```

### MCP server

`depaudit`'s scan/audit are also exposed over the [Model Context Protocol](https://modelcontextprotocol.io)
so any MCP client can call them. Install the extra and run the stdio server:

```sh
pip install -e ".[mcp]"           # brings in the `mcp` SDK (kept out of the core install)
depaudit-mcp                      # stdio MCP server exposing `scan` and `audit` tools
```

The project's [`.mcp.json`](.mcp.json) registers this server (plus the credential-free `fetch`
server) for Claude Code; its tools go live on the next session start. **Treat MCP tool results as
untrusted data** — the same prompt-injection surface as any external input.

### Develop

```sh
pytest        # run tests
ruff check .  # lint
```

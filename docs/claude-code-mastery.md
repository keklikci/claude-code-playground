# Mastering Claude Code via a Python Supply‑Chain Scanner

A multi‑session, hands‑on curriculum. The goal is to **master Claude Code as a product** by
building one genuinely useful security tool, introducing each Claude Code capability exactly
when the tool needs it.

**Capstone project — `depaudit`:** a Python CLI that audits a project's dependencies for
supply‑chain risk:
- known CVEs (via the free [OSV.dev](https://osv.dev) API — no key required),
- typosquatting against popular PyPI names,
- license compliance,
- package integrity / metadata checks,
- machine outputs (JSON + SARIF) and CI exit‑code gating.

This domain naturally pulls in CI/CD gating, PR‑review automation, and MCP integrations — the
exact capabilities worth mastering.

---

## How to use this roadmap (multi‑session)

- Each session, start with: *"We're resuming the Claude Code mastery roadmap. I'm on Module N — let's go."*
- Each module has the same shape: **Goal → What you build → CC capabilities practiced → Try‑these prompts → Mastery check.** Don't advance until the mastery check passes.
- Modules 1–8 grow the capstone in order. "Mini‑exercise" callouts are intentional throwaways for isolated concepts.
- Every major capability gets one module as its center of gravity, and is reinforced later (see the matrix at the bottom).

> **Progress tracker** — tick these as you finish:
> - [x] Module 0 — Orientation & the working loop
> - [x] Module 1 — Real project work + settings & permissions
> - [x] Module 2 — Instructions & memory (CLAUDE.md)
> - [x] Module 3 — Core feature work in Plan mode (OSV.dev)
> - [x] Module 4 — Skills (built‑in + authoring your own)
> - [ ] Module 5 — Subagents & custom agents
> - [ ] Module 6 — MCP servers (consume + build)
> - [ ] Module 7 — Hooks & automation
> - [ ] Module 8 — CI/CD, PR reviews & loops

---

## Module 0 — Orientation & the working loop

- **Goal:** Be fluent in the day‑to‑day Claude Code surface before writing project code.
- **What you build:** Nothing yet — configure your environment and explore the empty repo.
- **CC capabilities practiced:**
  - The REPL loop, sending prompts, reading streamed edits/diffs.
  - **Permission modes** (default / acceptEdits / plan / bypass) and how to cycle them (Shift+Tab); when to use **Plan mode**.
  - `!command` bash passthrough; `@file` references; `/help`, `/context`, `/config`, `/model`.
  - `/init` (you'll use it for real in Module 2).
- **Try these prompts:**
  - "Explain what permission mode I'm in and what each mode allows."
  - `!python --version` and `!git status` to see passthrough.
  - Toggle into Plan mode and ask for a trivial plan to feel the difference.
- **Mastery check:** You can switch permission modes deliberately and explain when you'd use Plan vs acceptEdits.

## Module 1 — Real project work + settings & permissions

- **Goal:** Drive multi‑file project work and lock down the harness with settings.
- **What you build:** `depaudit` skeleton — `pyproject.toml`, a `depaudit/` package, a Click/argparse CLI, and the first feature: **parse dependencies** from `requirements.txt` (and the active venv via `importlib.metadata`). One passing `pytest`.
- **CC capabilities practiced:**
  - Multi‑file creation/refactor, running tests, making git commits *through* Claude.
  - `.claude/settings.json` (shared) vs `.claude/settings.local.json` (personal, git‑ignored) vs `~/.claude/settings.json` (user).
  - `permissions.allow` / `deny` / `ask` rules (e.g. allow `Bash(pytest:*)`, `Bash(ruff:*)`; deny destructive commands); `defaultMode`.
- **Try these prompts:**
  - "Scaffold a Python CLI package `depaudit` with pyproject, a `parse` command, and a pytest. Then run the test."
  - "Add a settings.json that auto‑allows pytest and ruff but asks before any network command."
- **Mastery check:** You can explain which settings file a given rule belongs in, and Claude stops prompting you for `pytest`.

> **Mini‑exercise — context management:** Run `/context` to see token usage. Deliberately `/compact` mid‑task and notice what's preserved. Practice `/clear` to start a clean sub‑task. Goal: know *when* to compact vs clear vs start a new session.

## Module 2 — Instructions & memory (CLAUDE.md)

- **Goal:** Teach Claude your project's conventions so it needs fewer corrections.
- **What you build:** A real `CLAUDE.md` for `depaudit` (commands, layout, test/lint conventions, security coding rules). Add `depaudit/parsers/CLAUDE.md` (nested instructions) for parser‑specific rules.
- **CC capabilities practiced:**
  - `/init` to generate a first CLAUDE.md, then hand‑tune it.
  - Project vs user (`~/.claude/CLAUDE.md`) memory; nested CLAUDE.md; `@path` imports; the `#` shortcut to append a memory mid‑session.
  - What belongs in memory vs what doesn't (don't restate code/git history).
- **Try these prompts:**
  - `/init`, then "Tighten this CLAUDE.md: add our ruff config, our 'no bare except' rule, and that all network calls go through `depaudit/net.py`."
  - Type `# always pin OSV API responses with a timeout` to capture a rule live.
- **Mastery check:** A fresh session follows your conventions without being told; you can explain memory precedence.

## Module 3 — Core feature work in Plan mode (OSV.dev integration)

- **Goal:** Use Plan mode to design and ship a substantial, networked feature.
- **What you build:** The **vulnerability engine** — query OSV.dev for each dependency, map results to severity, and report. Add a `net.py` with timeouts/retries.
- **CC capabilities practiced:**
  - Plan mode end‑to‑end (explore → plan → approve → implement).
  - Managing context across a multi‑file feature; using subagents to explore (preview of Module 5).
  - Permission interplay (this is the first network feature — your Module 1 "ask before network" rule fires).
- **Try these prompts:**
  - "In Plan mode: design the OSV.dev integration — batch queries, error handling, and a `Finding` dataclass — then implement after I approve."
- **Mastery check:** `depaudit scan` flags a known‑vulnerable pinned package (e.g. an old `requests`/`urllib3`).

## Module 4 — Skills (built‑in + authoring your own)

- **Goal:** Use and create Skills — Claude Code's reusable, invocable procedures.
- **What you build:** Two custom skills + habitual use of built‑ins.
  - `/triage-cve` — given a CVE/advisory, summarize impact for *this* project and propose a remediation (pin/upgrade/replace).
  - `/add-scanner` — scaffold a new check module with its test, following project conventions.
- **CC capabilities practiced:**
  - Built‑in skills: `/code-review` and `/security-review` on your own diff; `/init`, `/loop` (later).
  - Authoring: `.claude/skills/<name>/SKILL.md`, frontmatter (`name`, `description`), when a skill auto‑triggers vs is user‑invoked, passing `args`, directory‑scoped skills.
- **Try these prompts:**
  - "Run `/security-review` on my OSV integration and fix anything real."
  - "Create a `/add-scanner` skill that scaffolds `depaudit/checks/<name>.py` + a test, matching our patterns."
- **Mastery check:** You can author a skill from scratch and explain how its `description` controls auto‑invocation.

## Module 5 — Subagents & custom agents

- **Goal:** Delegate work to parallel subagents and build a specialized one.
- **What you build:** **Typosquatting** + **license** checks, plus a custom researcher agent.
  - `.claude/agents/cve-researcher.md` — a read/web agent that investigates an advisory and returns structured remediation notes.
- **CC capabilities practiced:**
  - Built‑in agents: `Explore`, `Plan`, `general-purpose` — and *why/when* to delegate.
  - Custom agent files: frontmatter (`name`, `description`, `tools`, `model`), tool scoping.
  - **Parallel fan‑out** (research many packages at once); background agents; reading back only the conclusions.
- **Try these prompts:**
  - "Fan out: for each of my 12 top‑level deps, launch a subagent to check PyPI metadata for maintainer/age red flags; summarize the risky ones."
  - "Create a `cve-researcher` agent restricted to read + web tools."
- **Mastery check:** You can decide when delegating beats doing it inline, and you have a working custom agent.

## Module 6 — MCP servers (consume one, build one)

- **Goal:** Understand the Model Context Protocol both as a consumer and an author.
- **What you build:**
  - **Consume:** wire up an external MCP server (e.g. GitHub) via `.mcp.json` and use its tools.
  - **Build:** a Python MCP server (FastMCP) that exposes `depaudit`'s scan as an MCP tool, so *any* MCP‑aware client can call your scanner.
- **CC capabilities practiced:**
  - `.mcp.json` config; `claude mcp add`; transport types (stdio / http); listing/using MCP tools.
  - Authoring an MCP server in Python; tool schemas; returning structured results.
  - **Security framing:** treat MCP tool output as untrusted data (prompt‑injection surface) — directly relevant to your focus.
- **Try these prompts:**
  - "Add a stdio MCP server `depaudit-mcp` exposing a `scan(path)` tool; show me the config and a smoke test."
  - "Use the GitHub MCP tools to open an issue for each high‑severity finding."
- **Mastery check:** You can add an MCP server, call its tools, and articulate the injection risk of trusting tool results.

## Module 7 — Hooks & automation

- **Goal:** Make the harness enforce your workflow automatically.
- **What you build:** A hook set in `settings.json`:
  - **PreToolUse** matcher on `Bash` that blocks network/destructive commands you didn't intend.
  - **PostToolUse** on `Edit|Write` that auto‑runs `ruff` + `pytest`.
  - **Stop**/Notification hook to ping you when a long scan finishes.
- **CC capabilities practiced:**
  - Hook events (PreToolUse, PostToolUse, UserPromptSubmit, Stop, SubagentStop, SessionStart, PreCompact); matchers; reading the JSON passed on stdin; exit‑code semantics (block vs allow).
  - The `update-config` skill for safe edits to `settings.json`.
- **Try these prompts:**
  - "Add a PostToolUse hook: after any Edit/Write, run ruff and pytest and surface failures."
  - "Add a PreToolUse hook that denies `curl`/`wget` unless I'm in the net module."
- **Mastery check:** Editing a file auto‑triggers your lint+test gate; you can explain how a hook blocks a tool call.

## Module 8 — CI/CD, PR reviews & loops (capstone)

- **Goal:** Run Claude Code and `depaudit` outside the interactive REPL, in automation.
- **What you build:**
  - **SARIF output** from `depaudit` and a **GitHub Actions** workflow that scans on PRs and uploads to code scanning, gating merges by severity (exit codes).
  - **Claude in CI:** `anthropics/claude-code-action` reviewing PRs; `@claude` mentions; headless `claude -p "..." --output-format json` for scripted checks.
  - **Loops:** `/loop` to re‑scan on an interval or watch the OSV feed for new advisories affecting your deps.
- **CC capabilities practiced:**
  - Headless/print mode and `--allowedTools`; the GitHub Action; `/review` (PR) vs `/security-review` (branch diff); the loop skill; scheduled/recurring tasks.
- **Try these prompts:**
  - "Add `--format sarif` to depaudit and a GitHub Action that fails the build on any high‑severity finding."
  - "Set up `@claude` PR review and a headless security gate in CI."
  - `/loop 30m re-run depaudit scan and tell me if anything new appeared`.
- **Mastery check:** A PR triggers both `depaudit` (SARIF) and a Claude review automatically; you can run Claude headlessly.

---

## "...and so on" — appendix capabilities (lighter touch)

Folded into the modules above or covered as short detours:
- **Custom slash commands** = skills (Module 4).
- **Output styles** (`/output-style`) and **status line** (`statusline-setup` agent) — quick personalization detour.
- **Keybindings** (`~/.claude/keybindings.json`) — optional ergonomics detour.
- **Claude Agent SDK / scripting** — pointer for going beyond the CLI (Module 8 sets this up).
- **Workflow orchestration** (multi‑agent fan‑out at scale) — optional capstone stretch after Module 5.

---

## Capability coverage matrix

| Capability | Primary module | Reinforced in |
|---|---|---|
| Project work / multi‑file edits | 1 | 3, 5 |
| Settings & permissions | 1 | 7 |
| Context management | Mini (after 1) | 3 |
| Instructions / CLAUDE.md & memory | 2 | all |
| Plan mode | 3 | 0 |
| Skills (built‑in + authoring) | 4 | all |
| Subagents & custom agents | 5 | 3, 8 |
| MCP servers (use + build) | 6 | 8 |
| Hooks / automation | 7 | 1 |
| CI/CD & headless | 8 | — |
| PR reviews | 8 | 4 |
| Loops / scheduling | 8 | — |

---

When you're ready to start building, say **"Begin Module 1"**.

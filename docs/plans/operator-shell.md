# Operator Shell and Persistent Context Implementation Plan

> **For Hermes:** Implement this plan task-by-task with tests and frequent commits.

**Goal:** Make `attnndef` launch an interactive, persistent local-first operator shell while preserving the existing direct CLI commands.

**Architecture:** Add a small SQLite-backed context/profile store and an interactive shell service. The shell owns navigation only; persistence and configuration are separate library modules. Existing subcommands remain available and continue using the existing service code.

**Tech Stack:** Python stdlib (`sqlite3`, `pathlib`, `cmd`, `getpass`), pytest.

---

### Task 1: Add persistent operator context store

Files:
- Create `src/attnndef/context/__init__.py`
- Create `src/attnndef/context/store.py`
- Test `tests/test_context_store.py`

Implement profile/session persistence in SQLite with profile fields, current mode, selected target, round number, and session id. Use an explicit database path supplied by the caller; default is `~/.attnndef/state.db`. Secrets are represented by a credential reference only.

Verify with `pytest tests/test_context_store.py -q`.

### Task 2: Add first-run wizard and interactive shell

Files:
- Create `src/attnndef/ui/__init__.py`
- Create `src/attnndef/ui/interactive.py`
- Test `tests/test_interactive.py`

Implement a testable `InteractiveConsole` using injected `input` and output functions. On missing profile, collect operator/team/mode and optional network fields. Display a compact main menu and support Targets, Attack, Defense, Monitor, Flags, Competition, Learning, Evidence, Settings, and Exit. Do not perform fake operations; unimplemented areas say unavailable and return safely.

Verify with tests using scripted input.

### Task 3: Wire plain `attnndef` and `--state-db`

Files:
- Modify `src/attnndef/cli.py`
- Modify `pyproject.toml`
- Test `tests/test_cli.py`

Make subcommands optional. If no command is provided, launch the interactive shell. Add `--state-db` and `--debug`. Register the console script `attnndef=attnndef.cli:main`.

Verify `attnndef --help`, `attnndef --state-db /tmp/x` with scripted input, and all existing tests.

### Task 4: Documentation and verification

Files:
- Modify `README.md`
- Create `docs/operator-console.md`

Document first launch, state location, direct CLI compatibility, safe local scope, and current Phase 1 boundaries. Run the full test suite and commit.

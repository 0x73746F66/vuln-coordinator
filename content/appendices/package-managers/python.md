---
title: "Python — pip, Pipenv, Poetry, uv"
description: "Lockfile mechanics for the four Python dependency-management workflows."
weight: 20
---

## pip + `requirements.txt`

```bash
# Compile from a high-level requirements.in
pip-compile --generate-hashes requirements.in

# Coerce a transitive: pin it explicitly in requirements.in
# Then recompile
pip-compile --generate-hashes requirements.in

# Install with hash verification
pip install --require-hashes -r requirements.txt
```

`pip-compile` (from `pip-tools`) produces a fully-pinned `requirements.txt` from a constraint-style `requirements.in`. Transitive coercion means adding a constraint line for the transitive in `requirements.in` and recompiling. `--require-hashes` mandates `--hash=sha256:...` per entry — without it, the lockfile has no integrity check. Gotcha: native wheels (e.g., NumPy on Apple Silicon) have platform-specific hashes; use a `constraints.txt` separately if cross-platform.

## Pipenv (`Pipfile.lock`)

```bash
pipenv update requests

# Coerce a transitive — add to [packages] in Pipfile:
#   urllib3 = ">=2.0.7"
pipenv lock
pipenv sync     # install only what's in the lock
```

`[packages]` is production; `[dev-packages]` is dev-only — production VEX statements should ignore dev-package findings unless they ship. Integrity is per-entry `sha256`. Gotcha: `pipenv update` (no args) re-locks the entire graph; pass the package name explicitly to bump just one.

## Poetry (`poetry.lock`)

```bash
poetry update urllib3

# Coerce a transitive — pyproject.toml [tool.poetry.dependencies]:
#   urllib3 = ">=2.0.7"
poetry lock --no-update    # re-lock without bumping others
poetry install --sync
```

Poetry's constraint syntax distinguishes `^1.2.3` (next major), `~1.2.3` (next minor), `>=1.2.3` (open upper). For coercion, declare the transitive as a direct dep in `[tool.poetry.dependencies]` with the required floor. Gotcha: Poetry's resolver is exhaustive — `poetry lock` can take minutes on large graphs. Use `--no-update` when you only want to add a constraint.

## uv (`uv.lock`)

```bash
uv lock --upgrade-package requests

# Coerce a transitive: pin in pyproject.toml dependencies
uv lock

# CI: never re-resolve
uv sync --frozen
```

`uv` is the fastest of the Python lockers; `uv.lock` is TOML, human-readable, hash-locked. The frozen install in CI is the single biggest lever for build reproducibility. Gotcha: `uv` is comparatively new — the ecosystem is still catching up on tooling around it.

## Reachability

- `pip show <pkg>` shows direct/transitive relationships.
- `pydeps <module>` renders the import graph.
- `python -c "import sys; print('vuln_fn' in dir(__import__('pkg')))"` confirms the symbol exists.
- Runtime: `coverage.py` with `--branch` during a representative test run. A module imported but never run is `vulnerable_code_not_in_execute_path`.

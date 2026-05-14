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

## Developer gotchas — written for people who live in the code

You import Python modules daily; you skim `requirements.txt` once a release. These are the surprises that catch developers when triaging an SCA finding.

- **The scanner reads `requirements.txt`; your environment installed something else.** A loose pin like `requests>=2.20` lets your last `pip install` pick `2.32.3`, but the scanner sees `>=2.20` and may flag against the lowest version in the range. Fix: pin exact versions (`requirements.txt`-from-`pip-compile`, `Pipfile.lock`, `poetry.lock`, or `uv.lock`) so the *resolved* version is in source control. Check with `pip freeze | grep <pkg>` against the running container's site-packages, not your dev machine's.

- **`pip install -e .` and the scanner disagree.** Editable installs link to your source tree, not to a wheel. Scanners that walk `site-packages` may report your own package as a dep and miss CVEs in your declared deps that haven't been installed. Symptom: scanner shows fewer deps than `pip freeze`. Fix: use a full `pip install -r requirements.txt` in the image you actually scan.

- **`__init__.py` imports cascade — and reachability isn't just about your code.** `import pandas` runs `pandas/__init__.py` which imports `numpy`, `pyarrow`, `matplotlib` lazily-or-not. A CVE in `pyarrow` is reachable the moment `pandas` is imported, even if your code never references `pyarrow` directly. `pydeps` resolves it; manual grep doesn't.

- **Conditional imports hide reachability.** `try: import cChardet; except ImportError: import chardet` — both are reachable depending on what's installed at runtime. The scanner picks one; your prod env may run the other. Check both.

- **`pip install` versus `pip install --user` versus venv versus system Python.** Four installation locations. A CVE in the user-site `~/.local/lib/python3.11/site-packages` won't be in your container, but a dev running tests locally hits it. Scanners that walk file paths inside a container shouldn't see user-site at all — if they do, your Dockerfile may be doing something surprising like `COPY ~/.local` (rare but real).

- **`pyproject.toml` `[project.optional-dependencies]` are opt-in.** `pip install mypkg[dev]` installs them; `pip install mypkg` doesn't. The scanner may flag a CVE in `pytest` but your production install never had it. VEX with `component_not_present` is honest if the prod install command doesn't request the extra.

- **Build deps are installed in a build environment that's thrown away.** `[build-system] requires` (PEP 518) lists packages needed to *build* a wheel — `setuptools`, `wheel`, `cython`. pip creates an isolated env to run the build, then discards it. A CVE in `setuptools<70` may flag in your `pyproject.toml` but never touches your runtime. Build-env CVEs are runtime-not-affected.

- **C extensions and the wheel/sdist split.** `requirements.txt` says `numpy==1.26`; pip may install a prebuilt wheel for Linux x86_64 *or* fall back to building from sdist on a less-common platform. The wheel and the sdist can have different bundled vendored deps. Scanners that read `METADATA` see the same version; scanners that read shared-object linkage (in containers) see different libraries.

- **`pip` cached wheels survive `requirements.txt` changes.** `~/.cache/pip/wheels/` keeps built wheels. A CVE-affected version you bumped two months ago may still be in the cache; a Docker build that does `pip install` against a cached layer may install the cached version if the requirements line didn't change. Solution: `pip install --no-cache-dir` in production Dockerfiles.

- **`PYTHONPATH` and `sys.path` manipulation makes reachability fuzzy.** Code that does `sys.path.insert(0, '/opt/legacy')` may pull in a different version of a vulnerable package than what's in `site-packages`. Scanners only see what's on disk; reachability requires reading the bootstrapping logic.

- **Django/Flask middleware ordering changes the answer.** A CVE in a deserialisation library is only reachable if the middleware that calls it is in `MIDDLEWARE` / `app.register_blueprint`. The package is installed; the call site may not be wired up. Verify with `python manage.py check` plus grep on the middleware list.

- **Conda env vs venv vs system pip.** If your scanner ran against a Conda env, the metadata layout (`conda-meta/`) differs from pip's. Scanners that only understand pip miss conda-only installs entirely. For a Conda-based project, use `conda list --json` plus `osv-scanner` with the `conda-meta` glob.

## Reachability

- `pip show <pkg>` shows direct/transitive relationships.
- `pydeps <module>` renders the import graph.
- `python -c "import sys; print('vuln_fn' in dir(__import__('pkg')))"` confirms the symbol exists.
- Runtime: `coverage.py` with `--branch` during a representative test run. A module imported but never run is `vulnerable_code_not_in_execute_path`.

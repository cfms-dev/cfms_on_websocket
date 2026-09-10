# CFMS Python 3.15 migration playbook

## Contents

- Readiness inventory
- Dependency and wheel gates
- Cutover edit surface
- Source compatibility audit
- Validation and handoff

## Readiness inventory

Start from live files and preserve unrelated changes:

```powershell
git status --short
Get-Content -Raw pyproject.toml
Get-Content -Raw .python-version -ErrorAction SilentlyContinue
Get-Content uv.lock -TotalCount 20
rg -n --hidden --glob '!.git/**' '3\.14|>=3\.14|py314|cp314|Python 3\.14' .
```

Classify every match as one of:

- active support contract or interpreter selector;
- CI, packaging, release, or deployment behavior;
- a test asserting current policy;
- current documentation or example output;
- historical release note or migration record that should not be rewritten.

On the 2026-09-10 tree, active locations included:

- `pyproject.toml` and `uv.lock`;
- `.github/workflows/test.yml`, `performance.yml`, and `release.yml`;
- `tests/project/test_python_version_policy.py`;
- Python-version fixtures in `tests/maintenance/test_deployment.py`;
- `README.md`, `tests/README.md`, and `.github/workflows/README.md`;
- `AGENTS.md` and the `maintain-cfms-python` skill/reference;
- the ignored, untracked local `.python-version`.

Re-run the search. Do not use this list as a substitute for the current tree. Update diagnostic examples such as `docs/SERVER_DIAGNOSTICS_API.md` only if they present a current support/runtime claim; stable payload examples may intentionally show an older patch version.

## Dependency and wheel gates

First confirm the intended interpreter without changing the project environment:

```powershell
uv python find 3.15
uv run --python 3.15 --no-project python -c "import sys; print(sys.version)"
uv lock --check
```

For RC readiness in GitHub Actions, request the exact release candidate or use the `3.15` range with `allow-prereleases: true`. For final cutover, request stable `3.15` and remove prerelease fallback unless it is intentionally retained for a future-version preview lane.

Probe wheel availability separately because `uv lock --check` and a successful resolver do not install artifacts:

```powershell
uv sync --dry-run --python 3.15 --no-dev --no-build
uv sync --dry-run --python 3.15 --all-groups --no-build
uv sync --dry-run --python 3.15 --no-dev --extra cluster --no-build
uv sync --dry-run --python 3.15 --no-dev --extra mysql --no-build
uv sync --dry-run --python 3.15 --no-dev --extra postgresql --no-build
uv sync --dry-run --python 3.15 --no-dev --extra ext_oidc_sso --no-build
uv sync --dry-run --python 3.15 --no-dev --extra ext_http_api --no-build
uv sync --dry-run --python 3.15 --no-dev --extra ext-scheduling-cluster --no-build
```

Run equivalent probes on every supported OS and architecture. `--no-build` intentionally answers the wheel-availability question. If source builds are a supported deployment path, validate them separately in a disposable environment with documented compilers, headers, Rust/C toolchains, and system libraries.

For each failure, record the package, locked version, platform tag, dependency path, selected extra/group, available sdist/wheels, and upstream compatibility statement. Use `uv tree --locked --invert --package <name>` to identify why the package is present. Never override an exact transitive dependency such as `pydantic-core` independently of its owning package.

Before cutover, intentionally re-resolve under the final interpreter:

```powershell
uv lock --python 3.15
uv lock --check
```

Review all version and marker changes. Do not edit `uv.lock` manually or upgrade unrelated packages without explaining why the 3.15 resolution requires them.

## Cutover edit surface

Make the floor change coherent:

1. Change `project.requires-python` to `>=3.15`.
2. Regenerate `uv.lock` with Python 3.15 and verify its `requires-python` value and marker branches.
3. Replace active 3.14 CI pins with 3.15 in test, performance, and release workflows. Ensure all required OS/database/provider jobs still run; dropping 3.14 means removing its compatibility lane, not silently reducing backend coverage.
4. Update the version-policy test and deployment/release fixtures whose purpose is to assert the active floor.
5. Update current support documentation, workflow documentation, operator prerequisites, and release notes/changelog entry as project convention requires.
6. Update `AGENTS.md`, `maintain-cfms-python/SKILL.md`, and its Python-version reference so future work targets 3.15 and no longer prohibits 3.15-only code for the old-floor reason. Preserve unrelated architectural rules and the Pluggy annotation exception.
7. Update `.python-version` for the local workspace if present. It was ignored and untracked on 2026-09-10; report that fact and do not force-add it unless repository policy is deliberately changed.
8. Re-run the full version search and retain only historical or intentionally illustrative 3.14 references.

Prefer a mechanical support-floor commit before optional feature-adoption commits. This makes dependency and behavior regressions attributable and keeps a rollback recoverable. Do not add `sys.version_info` branches or backports to preserve 3.14 after the declared support removal.

## Source compatibility audit

Parse all source files with the target interpreter without creating `__pycache__`:

```python
from pathlib import Path

paths = [
    path
    for root in (Path("src"), Path("tests"), Path("tools"))
    for path in root.rglob("*.py")
]
for path in paths:
    compile(path.read_bytes(), str(path), "exec", flags=1024, dont_inherit=True)
print(f"parsed {len(paths)} files")
```

Run targeted `rg` searches for the removals and changed signatures in the research snapshot. Also inspect transitive native packages; source scans cannot see their C API use.

Pay special attention to:

- SQLite positional arguments and callback registration signatures;
- custom import loaders, extension discovery, import-time registration, and optional imports;
- `TYPE_CHECKING` imports inspected through Pluggy or other runtime frameworks;
- text I/O without explicit encodings at persistent or external boundaries;
- Base64 validation and security-sensitive decoding;
- runtime use of `Protocol`, `TypedDict`, AST construction, and private typing implementation classes;
- standard-library module version attributes;
- thread shutdown, interpreter finalization, and native extensions;
- Windows and POSIX differences in release/deployment paths.

Do not convert to 3.15 features during this audit unless the conversion fixes a demonstrated compatibility issue. In particular, global lazy imports can reorder failures and registration side effects; UTF-8-by-default can conceal missing format contracts; `frozendict` can break consumers that require a mutable concrete `dict`.

## Validation and handoff

Before pytest, read `maintain-cfms-python/references/testing-integrity.md`. If `src/app.db` exists, create and record a consistent snapshot:

```powershell
uv run --locked python .codex/skills/maintain-cfms-python/scripts/snapshot_test_state.py
```

After the cutover metadata and lockfile select 3.15, run the narrowest version-policy, dependency-sensitive, and changed-domain tests first. Expand to the required integration matrix, optional backends, maintenance CLI, release-bundle checks, and full suite only as warranted. Exercise developer warnings in focused runs and attribute them to project or dependency code; do not suppress them globally.

Build the distributable release through the repository's existing release path and inspect its metadata. Verify installation into a clean Python 3.15 environment, server startup/shutdown, extension discovery, configuration load/write, WebSocket behavior, SQLite plus supported external databases, backup/export/import, and deployment/rollback workflows according to the claimed release surface.

Before handing off:

- review `git diff` and lockfile resolution changes;
- run the active 3.14 reference search again;
- report exact Python and package versions, platforms, extras, tests, warnings, skipped checks, and database snapshot;
- distinguish wheel-backed installs from source builds;
- list unresolved blockers instead of calling the migration complete;
- use repository rollback/redeploy mechanisms if the cutover must be reverted; do not reintroduce hidden dual-version branches.

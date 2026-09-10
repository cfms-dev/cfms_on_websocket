---
name: migrate-cfms-python-315
description: Prepare, execute, or review the CFMS on WebSocket cutover to Python 3.15 while dropping Python 3.14, including prerelease readiness, dependency and wheel compatibility, source/API audits, project metadata, CI, documentation, and safe validation. Use only for this repository's Python 3.15 migration or post-cutover cleanup; use maintain-cfms-python for ordinary Python maintenance that does not change the supported Python floor.
---

# Migrate CFMS to Python 3.15

Raise the repository's actual runtime contract, not merely the version string. Preserve CFMS architecture, protocol behavior, transaction ownership, storage formats, extension lifecycle, and test integrity while changing the minimum supported interpreter from 3.14 to 3.15.

Use this skill together with the repository's `maintain-cfms-python` skill. Its architecture and test-safety rules remain authoritative unless this skill deliberately replaces the Python-version policy during the cutover.

## Choose the operating mode

- **Readiness:** assess or improve 3.15 compatibility while `requires-python` remains `>=3.14`. A prerelease CI lane, isolated dependency probe, or source audit belongs here. Do not introduce 3.15-only syntax or APIs into production code.
- **Cutover:** change the floor to `>=3.15` and remove 3.14 support only when the user explicitly requests the migration. Update the entire declared support surface coherently; do not leave a nominal 3.14 promise or add compatibility shims for the version being dropped.
- **Post-cutover:** adopt a 3.15 feature only for a demonstrated readability, correctness, security, observability, or measured performance benefit. Keep feature adoption separate from the mechanical floor change when practical.

Read [references/python-315-rc2-research.md](references/python-315-rc2-research.md) before making version-sensitive decisions. It records the 2026-09-10 evidence and known repository findings, but it is a snapshot rather than evergreen authority. Read [references/migration-playbook.md](references/migration-playbook.md) when changing files, dependencies, CI, or tests.

## Re-establish current facts

At every invocation that may change code or policy:

1. Confirm the host OS, nearest `AGENTS.md`, `git status`, and unrelated user changes.
2. Read the live `pyproject.toml`, `uv.lock`, `.python-version` if present, version-policy tests, workflows, deployment/release tooling, and support documentation. Do not assume the research snapshot still matches the tree.
3. Check the current Python 3.15 release page, versioned What's New document, deprecation index, and release schedule. Python 3.15.0rc2 was still a preview on 2026-09-10; do not carry that status forward without verification.
4. Query exact locked package versions and test installation for every supported OS, architecture, dependency group, and optional extra. A successful resolution or an up-to-date universal lockfile does not prove that a usable wheel exists.
5. State which mode is active and the support contract being preserved or changed before editing.

Use official Python documentation and PEPs for language/runtime facts, exact package documentation or PyPI artifacts for dependency compatibility, and live repository files for project policy. When implementation docs and a PEP differ, prefer the versioned Python 3.15 documentation.

## Enforce cutover gates

Do not declare the cutover ready until all applicable gates pass:

- The intended production release is available. A release candidate requires explicit authorization for production use even after ABI freeze.
- Core dependencies, development tools, and every supported optional extra install under CPython 3.15 on every deployment/CI platform. Prefer published wheels for native dependencies; any source-build exception must be an explicit, reproducible deployment decision.
- The locked environment can be recreated from scratch with `uv` under 3.15. Review the resolution diff instead of editing `uv.lock` manually.
- Source, tests, maintenance commands, release bundles, extension loading, and configured database/provider paths pass their proportionate checks under 3.15.
- Removed APIs, changed call signatures, runtime deprecations, encoding behavior, annotation introspection, import-time side effects, and platform-specific behavior have been audited.
- All 3.14 support claims and pins have either been updated or intentionally retained as historical examples.

If a gate fails, keep the repository in readiness mode and report the exact package/API, version, platform, extra, and evidence. Do not mask a missing wheel with an unreviewed compiler toolchain, replace a dependency with a different contract, or weaken a feature to make the probe pass.

## Apply 3.15 deliberately

- Keep explicit encodings at protocol, configuration, archive, credential, subprocess, and other persistence/interchange boundaries even though UTF-8 mode is now the default. The default change is compatibility evidence, not permission to make file formats locale-implicit.
- Use `lazy import` only after measuring a meaningful startup or memory problem and tracing import-time registration, provider discovery, Pluggy hooks, configuration, logging, and extension side effects. Do not enable global lazy imports for this stateful server as a migration shortcut.
- Use `frozendict` only for a genuinely immutable mapping contract after confirming downstream code accepts `Mapping` rather than requiring or mutating a `dict`.
- Use `sentinel` when a public or cross-module missing-value state benefits from stable identity, concise representation, typing, and pickling. Do not replace every private `object()` sentinel mechanically.
- Use comprehension unpacking only when it is clearer than the existing nested comprehension or `itertools` form and preserves ordering, overwrite, and laziness semantics.
- Use `TypedDict(closed=True)` or `extra_items=...` for static shape precision. Keep runtime validation with Pydantic or JSON Schema at untrusted CFMS boundaries.
- Treat `TypeForm` and `@typing.disjoint_base` as specialized typing tools, not general refactors. The latter is primarily for built-in or extension-type modeling.
- Preserve explicit string annotations on Pluggy hooks whose types are imported only under `TYPE_CHECKING`; Python 3.15 does not make runtime signature inspection harmless.
- Treat free-threaded builds, the JIT, tail-calling interpreter, subinterpreters, and new profiling facilities as separate operational choices. None changes CFMS's thread-safety, SQLAlchemy-session, provider, or extension invariants automatically.
- Do not replace `re.match()` solely because `re.prefixmatch()` is the newer name; `match()` is soft-deprecated with no planned removal.

## Complete and verify the change

Use `uv` for interpreter, lock, environment, and package operations. Never run Ruff directly. Before any pytest invocation, read the testing-integrity reference from `maintain-cfms-python` and snapshot `src/app.db` with its provided script when the database exists.

Run the narrowest meaningful 3.15 checks first, then the affected domain and required integration/release checks. Include optional backends that the release claims to support. Review every lock, formatter, and generated-file change before expanding validation.

The handoff must distinguish:

- verified interpreter and package versions;
- platforms, extras, and commands actually exercised;
- wheel availability versus source-build success;
- tests passed, warnings observed, and checks skipped;
- the database snapshot path, if tests ran;
- remaining blockers or assumptions;
- every support-policy file changed, including ignored local files that cannot be part of the commit.

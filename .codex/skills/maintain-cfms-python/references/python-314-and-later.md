# Python 3.14 and later

## Contents

- Version policy
- Adopt deliberately
- Annotation rules
- Typing and data shapes
- Deprecation workflow
- Python 3.15 preview boundary
- Primary sources

## Version policy

The live repository is authoritative. At the time this reference was written:

- `requires-python = ">=3.14"` and `.python-version` is `3.14`.
- The workspace interpreter is CPython 3.14.6.
- Python 3.15.0b4 is a prerelease; final 3.15.0 is scheduled for October 2026.

Write production syntax and APIs for Python 3.14 until the declared floor is intentionally raised. A newer local interpreter is not permission to use its features. When considering a floor change, check every dependency, deployment platform, CI job, operator workflow, and migration path first.

## Adopt deliberately

### Deferred annotations (PEP 649 and PEP 749)

Use Python 3.14's default lazy annotation semantics. Remove the need for most quoted forward references. Do not add `from __future__ import annotations`; it retains PEP 563 stringized behavior, is deprecated, and the repository has a policy test rejecting it.

Do not assume laziness means annotations can never execute. Access through `inspect.signature()`, `__annotations__`, `typing.get_type_hints()`, or `annotationlib` may evaluate names. Runtime frameworks can therefore expose missing imports or side effects.

### Template strings (PEP 750)

Do not replace f-strings with t-strings mechanically. A t-string produces a `Template`, not `str`, and is useful only with an intentional renderer that processes interpolations—for example a well-designed escaping or DSL boundary. Do not invent a renderer for one string or imply that a t-string alone makes SQL, shell, HTML, logs, or protocol data safe.

Use SQLAlchemy parameter binding for SQL and argument sequences for subprocesses. Continue to use ordinary f-strings for trusted display text when no structured renderer is needed.

### Compression namespace and Zstandard (PEP 784)

Python 3.14 adds `compression.zstd` and makes `compression.gzip`, `compression.bz2`, `compression.lzma`, and `compression.zlib` the preferred import names. The top-level modules remain supported and are not deprecated. Do not mass-change existing `import lzma` or `import zlib` solely for novelty.

Do not replace CFMS backup compression with Zstandard without specifying archive compatibility, detection/versioning, dependencies across supported runtimes, failure recovery, and migration. A faster codec is a format change, not a local refactor.

### Concurrency features

`concurrent.interpreters`, `InterpreterPoolExecutor`, improved free-threaded builds, and asyncio inspection are not drop-in optimizations for this server. CFMS has process-global configuration, provider managers, Pluggy state, locks, threads, ORM sessions, and third-party C extensions. Require measurement and a design covering isolation, shared state, extension support, shutdown, and database connections before adoption.

The server currently uses `websockets.sync`. Do not convert it to asyncio merely to use an asyncio feature. For actual asyncio code, avoid the deprecated policy system; prefer `asyncio.run()` or `asyncio.Runner` and a `loop_factory` when needed.

### Syntax-only changes

Python 3.14 permits `except A, B:` without parentheses. Choose the clearest form and avoid syntax-only churn. Never place `return`, `break`, or `continue` in `finally`; Python 3.14 emits a `SyntaxWarning` for control flow that exits a `finally` block because it can discard exceptions.

## Annotation rules

Use normal unquoted annotations when names are available at evaluation time. Use `annotationlib.get_annotations()` with the least powerful format that meets the need:

- `Format.STRING` when only source-like names are required;
- `Format.FORWARDREF` when unresolved names must be represented safely;
- `Format.VALUE` only when actual runtime values are required and evaluation is expected.

Do not read, write, delete, or mutate `__annotations__` directly. Do not depend on private `typing` implementation classes; use `typing.get_origin()` and `typing.get_args()`.

### Pluggy exception

Pluggy 1.6 obtains hook parameter names through `inspect.signature()`. Under Python 3.14, this can evaluate deferred annotations. If a hook annotation names a type imported only under `TYPE_CHECKING`, use an explicit string on both the hook specification and implementation:

```python
if TYPE_CHECKING:
    from sqlalchemy.orm import Session as OrmSession


@hookimpl
def ext_before_file_upload_finalize(
    session: "OrmSession",
    id: str,
    path: str,
    sha256: str,
) -> None:
    ...
```

Do not quote all annotations globally to solve this local framework boundary.

## Typing and data shapes

Prefer Python 3.14-native forms:

- `list[str]`, `dict[str, Any]`, and `X | None` rather than legacy aliases;
- `class Box[T]:` / `def choose[T](...)` for genuine generics;
- `Self` for fluent or alternative constructors returning the current class;
- `StrEnum` for values that cross configuration/protocol boundaries as strings;
- frozen, slotted dataclasses for immutable decisions or snapshots;
- `collections.abc` for behavioral input types and `typing` for special typing constructs.

Keep annotations truthful and useful. Do not replace a precise type with `Any` to silence a checker, add `cast()` without a runtime invariant, or create a protocol only to avoid importing an existing concrete project contract. Keep Pluggy `TYPE_CHECKING` annotations quoted as described above.

Use `datetime.datetime.now(datetime.UTC).date()` rather than `datetime.date.today()` so the date has an explicit UTC basis. Use `datetime.UTC`, not `datetime.timezone.utc`. Use aware datetimes for absolute timestamps; preserve existing Unix-float protocol/database contracts unless an explicit migration changes them.

## Deprecation workflow

Before changing an allegedly deprecated API:

1. Search the source and lockfile.
2. Identify the exact owning package and installed version.
3. Reproduce the warning with developer warnings visible when safe.
4. Read the official documentation, deprecation entry, replacement semantics, and migration guide for that version.
5. Check all call sites and behavior differences.
6. Make the narrowest change and add a behavioral regression test when behavior can change.

Do not use undocumented or private APIs. Relevant Python 3.14 deprecations include:

- `asyncio.iscoroutinefunction()` → `inspect.iscoroutinefunction()`;
- the asyncio policy system → `asyncio.run()` / `Runner` with `loop_factory`;
- `os.popen()` / `os.spawn*` are soft-deprecated → `subprocess`;
- `argparse.FileType` → open/manage the resource after parsing;
- `PurePath.as_uri()` → `Path.as_uri()`;
- `PurePath.is_reserved()` → `os.path.isreserved()` on Windows;
- `typing.ByteString` / `collections.abc.ByteString` → `Buffer` or an explicit union;
- runtime package `__version__` attributes only when the package documents them; otherwise use `importlib.metadata.version("distribution-name")`.

Do not blanket-upgrade adjacent code. Existing top-level compression imports, for example, are not deprecated.

## Python 3.15 preview boundary

As of 2026-07-28, Python 3.15 is at beta 4 and its docs are explicitly draft. Lazy imports, `frozendict`, the `sentinel` built-in, comprehension unpacking, TypedDict extra items, UTF-8 default encoding, and other 3.15 features are useful for future planning only. Do not use them in production while the floor is 3.14.

Use 3.15 prereleases only as a separate compatibility lane to discover warnings and removals. Do not regenerate the lockfile or rewrite code under 3.15 unless the task explicitly includes forward compatibility and dependency support is verified.

## Primary sources

- [What's new in Python 3.14](https://docs.python.org/3.14/whatsnew/3.14.html)
- [Python 3.14 deprecations](https://docs.python.org/3.14/deprecations/)
- [Annotations best practices](https://docs.python.org/3.14/howto/annotations.html)
- [`annotationlib`](https://docs.python.org/3.14/library/annotationlib.html)
- [`typing`](https://docs.python.org/3.14/library/typing.html)
- [PEP 649](https://peps.python.org/pep-0649/) and [PEP 749](https://peps.python.org/pep-0749/)
- [PEP 750 template strings](https://peps.python.org/pep-0750/)
- [PEP 784 Zstandard](https://peps.python.org/pep-0784/)
- [Python 3.15 release schedule](https://peps.python.org/pep-0790/)
- [Draft What's new in Python 3.15](https://docs.python.org/3.15/whatsnew/3.15.html)

Prefer the versioned library documentation over a PEP when final implementation details differ; the Python docs explicitly note that PEPs are not generally updated after implementation.

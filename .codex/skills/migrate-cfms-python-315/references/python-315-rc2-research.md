# Python 3.15 RC2 research snapshot

## Scope and currency

This evidence snapshot was prepared on 2026-09-10 for CFMS on WebSocket. Python 3.15 and package availability are time-sensitive. Recheck all linked sources before a migration or dependency decision; do not treat version numbers or wheel findings here as current after this date.

## Release status

Python 3.15.0rc2 was released on 2026-09-01 as the final planned release candidate. CPython states that the 3.15 ABI will not change after this point and that wheels built against a 3.15 release candidate will work with future 3.15 releases. The same release page calls RC2 a preview that is not recommended for production. Python 3.15.0 final is scheduled for 2026-10-01.[^1] The versioned What's New page identifies itself as draft prerelease documentation.[^2]

The practical consequence is a two-stage policy:

- RC2 is suitable for compatibility discovery, CI experiments, wheel publication, and source/API audits.
- Production cutover should wait for the final release unless the project owner explicitly accepts prerelease production risk.

The 3.15 branch is scheduled for approximately two years of bugfix releases followed by three years of source-only security releases, ending around October 2031.[^3]

## Changes that affect migration decisions

| Change | Verified 3.15 behavior | CFMS decision |
|---|---|---|
| Explicit lazy imports (PEP 810) | `lazy import` and `lazy from` defer module execution to first use. The feature is opt-in; exceptions and side effects move to the reification point. Global mode and filters also exist.[^2][^4] | Do not enable globally. Measure startup first and audit extension registration, Pluggy, providers, configuration, logging, and optional-import failure timing before using it locally. |
| `frozendict` (PEP 814) | New immutable built-in mapping, distinct from `dict`, hashable only when keys and values are hashable; insertion order is retained while equality ignores order.[^2][^5] | Consider for real immutable snapshots or decisions only. Check consumers for `Mapping` semantics and serialization support. |
| `sentinel` (PEP 661) | New built-in sentinel type preserves identity when copied, participates in union type expressions, and is pickleable when importable by module and name.[^2][^6] | Useful for stable public/cross-module missing states; avoid mechanical replacement of private sentinels. |
| Comprehension unpacking (PEP 798) | `*` and `**` are accepted in list/set/dict comprehensions and generator expressions, with the documented flattening and later-key-wins behavior.[^2][^7] | Syntax-only opportunity after the floor changes; adopt only when clearer and semantics are unchanged. |
| UTF-8 default (PEP 686) | UTF-8 mode is enabled by default independently of locale; `PYTHONUTF8=0` or `-X utf8=0` restores the prior mode.[^2][^8] | Keep explicit encodings for CFMS configuration, manifests, archives, credentials, logs, and interchange. Test locale-independent behavior; do not rely on an ambient mode for persisted formats. |
| Package startup configuration (PEP 829) | `.start` entry-point files make executable startup hooks auditable; `.pth` import lines are silently deprecated, and `.pth` files must use `utf-8-sig` rather than locale decoding.[^2][^9] | CFMS currently has no repository `.pth` or `.start` file. Audit installed tooling and extensions before assuming startup is unchanged. |
| Typing changes | `TypedDict` gains `closed` and `extra_items`; `TypeForm` represents values that are type expressions; `@typing.disjoint_base` models special disjoint inheritance.[^2][^10][^11][^12] | Use `TypedDict` improvements for static precision only; retain runtime validation at untrusted boundaries. The other features need a concrete typing contract. |
| Profiling and observability | The new `profiling` package contains tracing and the Tachyon sampling profiler; frame pointers are enabled by default on supporting builds. `cProfile` remains an alias, while `profile` is deprecated for removal in 3.17.[^2] | Potential diagnostics benefit. Treat production attachment, permissions, overhead claims, and platform availability as a separate operational review. |
| Runtime variants | Windows x86-64 official builds use the tail-calling interpreter; JIT performance improved; free-threaded builds gain stable-ABI work.[^1][^2] | Benchmark the actual CFMS workload. Do not infer thread safety, replace locks, share SQLAlchemy sessions, or enable free-threading/JIT as part of the floor bump. |

## Compatibility hazards from 3.15

The Python-level removals most worth scanning in this repository and its tools are:

- `importlib` and `zipimport` loader `load_module()` methods; use `exec_module()`.
- `importlib.resources.files(package=...)`; pass the anchor positionally or by its current documented name.
- `pathlib.PurePath.is_reserved()`; use `os.path.isreserved()` on Windows.
- `platform.java_ver()`, `CGIHTTPRequestHandler`, `sre_compile`, `sre_constants`, `sre_parse`, `code.co_lnotab`, `ctypes.SetPointerType()`, `typing.no_type_check_decorator`, old `wave` marker methods, undocumented `NamedTuple` keyword-field construction, and zero-field `TypedDict("TD")` / `TypedDict("TD", None)`.[^2]
- AST node construction now raises `TypeError` for missing required fields or unknown fields instead of emitting a warning.[^2]
- `sqlite3.connect()` parameters after `database` are keyword-only. The leading parameters of `create_function()` and `create_aggregate()`, and callback parameters of authorizer/progress/trace setters, are positional-only.[^2]

New or newly visible deprecations relevant to forward maintenance include `typing.ByteString` and `collections.abc.ByteString`, `hashlib`'s `string=` initial-data name, alternative alphabets that still accept `+` or `/` in Base64 decoding, stdlib module `__version__`/`version`/`VERSION` attributes, imports in `.pth` files, protocol `isinstance` checks without an explicit `@runtime_checkable`, and `profile`.[^2][^13]

`re.match()` is only soft-deprecated in favor of the clearer `re.prefixmatch()` name, and the documentation says there is no plan to remove the older spelling. Existing code need not churn solely for this rename.[^2]

C-extension dependencies need their own audit. Python 3.15 removes or replaces several long-deprecated Unicode, weak-reference, import, and initialization C APIs. A pure-Python source scan cannot prove that transitive native extensions are compatible.[^13]

## Repository evidence on 2026-09-10

The live repository declared `requires-python = ">=3.14"`; `uv.lock` recorded the same floor; GitHub test, performance, and release workflows pinned 3.14; documentation and policy tests contained additional support claims. The local `.python-version` contained `3.14` but was ignored and untracked, so changing it alone would not alter the committed support contract.

A CPython 3.15.0rc2 parser successfully parsed all 340 Python files under `src`, `tests`, and `tools`. Targeted searches found no project use of the Python-level removed APIs listed above. The repository's direct `sqlite3.connect()` calls already passed non-database arguments by keyword where present. These checks establish syntax and obvious API readiness only; they do not replace imports, dependency installation, tests, or runtime behavior.

The source deliberately uses explicit encodings on most configuration and persistence boundaries. Keep that property after PEP 686. It also contains import-time extension/provider behavior and Pluggy signature inspection, making global lazy imports a high-risk, non-mechanical optimization.

## Dependency and tooling evidence on 2026-09-10

The lockfile contained 92 packages. A Windows x86-64 `uv sync --dry-run --python 3.15 --no-build` probe demonstrated why resolution is not enough:

- Core runtime installation stopped at `pydantic-core==2.46.5`, which had no compatible CPython 3.15 wheel in the locked release. Pydantic is heavily used in production CFMS code. PyPI did show CPython 3.15 wheels for a different `pydantic_core` release, so re-resolve the supported Pydantic pair rather than overriding its exact core dependency manually.[^14][^14-newer]
- The development group stopped at `PyYAML==6.0.3`, whose published wheels did not include CPython 3.15. It is a transitive development/tooling concern rather than direct CFMS runtime usage.[^15]
- The PostgreSQL extra stopped at `psycopg2-binary==2.9.12`, whose published wheels reached CPython 3.14 but not 3.15. Do not switch to another driver merely to pass the probe; that changes the SQLAlchemy driver and deployment contract.[^16]
- `orjson==3.12.0`, a native protocol dependency, did publish CPython 3.15 Windows wheels.[^17]

The absence of a wheel does not prove a source build cannot succeed. It does prove that a wheel-only deployment gate fails. Decide separately whether each production platform permits reproducible source builds and has the required C/Rust toolchain and system libraries.

The installed `uv` could find CPython 3.15.0rc2, but uv classified Python 3.15 prereleases as Tier 2 on the research date.[^18] For GitHub Actions before general availability, `actions/setup-python` requires either an exact prerelease/dev request or `allow-prereleases: true` with an `x.y` request.[^19] Remove prerelease-only configuration when switching to final 3.15 unless it still serves a deliberate future-preview lane.

## Sources

[^1]: Python Software Foundation, [Python 3.15.0rc2 release](https://www.python.org/downloads/release/python-3150rc2/), 2026-09-01.
[^2]: Python Software Foundation, [What's new in Python 3.15](https://docs.python.org/3.15/whatsnew/3.15.html), 3.15.0rc2 documentation, accessed 2026-09-10.
[^3]: Python Software Foundation, [PEP 790: Python 3.15 release schedule](https://peps.python.org/pep-0790/), updated 2026-09-01.
[^4]: Python Software Foundation, [PEP 810: Explicit lazy imports](https://peps.python.org/pep-0810/).
[^5]: Python Software Foundation, [PEP 814: Add frozendict built-in type](https://peps.python.org/pep-0814/).
[^6]: Python Software Foundation, [PEP 661: Sentinel values](https://peps.python.org/pep-0661/).
[^7]: Python Software Foundation, [PEP 798: Unpacking in comprehensions](https://peps.python.org/pep-0798/).
[^8]: Python Software Foundation, [PEP 686: Make UTF-8 mode default](https://peps.python.org/pep-0686/).
[^9]: Python Software Foundation, [PEP 829: Package startup configuration files](https://peps.python.org/pep-0829/).
[^10]: Python Software Foundation, [PEP 728: TypedDict with typed extra items](https://peps.python.org/pep-0728/).
[^11]: Python Software Foundation, [PEP 747: Annotating type forms](https://peps.python.org/pep-0747/).
[^12]: Python Software Foundation, [PEP 800: Disjoint bases in the type system](https://peps.python.org/pep-0800/).
[^13]: Python Software Foundation, [Python 3.15 deprecations index](https://docs.python.org/3.15/deprecations/index.html), 3.15.0rc2 documentation, accessed 2026-09-10.
[^14]: Python Package Index, [`pydantic_core` 2.46.5 files](https://pypi.org/project/pydantic_core/2.46.5/), accessed 2026-09-10.
[^14-newer]: Python Package Index, [`pydantic_core` latest release files](https://pypi.org/project/pydantic_core/), accessed 2026-09-10.
[^15]: Python Package Index, [PyYAML 6.0.3 files](https://pypi.org/project/PyYAML/6.0.3/), accessed 2026-09-10.
[^16]: Python Package Index, [`psycopg2-binary` 2.9.12 files](https://pypi.org/project/psycopg2-binary/2.9.12/), accessed 2026-09-10.
[^17]: Python Package Index, [`orjson` 3.12.0 files](https://pypi.org/project/orjson/3.12.0/), accessed 2026-09-10.
[^18]: Astral, [uv Python support policy](https://docs.astral.sh/uv/reference/policies/python/), accessed 2026-09-10.
[^19]: GitHub, [`actions/setup-python` prerelease guidance](https://github.com/actions/setup-python/blob/main/docs/advanced-usage.md#allow-pre-releases), accessed 2026-09-10.

# Changelog fragments

Every pull request with a user-visible change must add one Towncrier fragment.
Use the issue or pull-request number and one of the configured categories:

```powershell
uv run --locked towncrier create 123.added.md
uv run --locked towncrier create 456.fixed.md
```

Use an orphan fragment when no issue number exists:

```powershell
uv run --locked towncrier create +short-description.changed.md
```

Write one concise, user-facing change per fragment. Available categories are
`security`, `removed`, `deprecated`, `added`, `changed`, and `fixed`. Preview
the pending release notes without changing files:

```powershell
uv run --locked towncrier build --draft --version 0.7.0
```

Maintainers prepare a release with `tools/manage_release.py`; do not edit a
released section of `CHANGELOG.md` manually. A maintainer may apply the
`skip-changelog` pull-request label when a change has no user-visible effect.

Use either an explicit target version or a semantic increment:

```powershell
uv run --locked python tools/manage_release.py prepare 0.7.0
uv run --locked python tools/manage_release.py prepare --bump minor
```

The command requires a clean worktree, previews the release notes, synchronizes
all core-owned version metadata, updates `uv.lock`, builds the changelog, and
removes the consumed fragments. Review and commit the resulting diff before
creating the matching `vX.Y.Z` tag.

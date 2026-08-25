# GitHub Actions Workflows

## test.yml - Automated Testing

This workflow runs the pytest test suite automatically when:
- Code is pushed to any branch
- A pull request is opened or updated
- Another workflow calls it as a reusable test gate

### What it does:
1. Sets up a Python 3.14 environment
2. Installs project dependencies and test requirements
3. Requires a Towncrier fragment on pull requests unless the pull request has
   the `skip-changelog` label
4. Creates necessary directories for the server
5. Runs the full test suite with pytest
6. Runs focused SQLite-to-MySQL and MySQL-to-SQLite migration tests against
   MySQL 8.4 and 9.7 LTS services
7. Uploads test results and logs as artifacts (retained for 7 days)

### Configuration:
- **Timeout**: 10 minutes per test run
- **Python version**: Tests run on Python 3.14
- **Database integration**: Cross-engine migration tests run on MySQL 8.4 and
  9.7 LTS
- **Artifacts**: Test cache and server logs are uploaded for debugging

### Viewing Results:
- Check the "Actions" tab in the GitHub repository
- Test results will show pass/fail status for each Python version
- Download artifacts to review detailed logs if tests fail

## release.yml - Deployment Bundles

This workflow runs when a stable `vX.Y.Z` tag is pushed. The tag must match
`project.version` in `pyproject.toml`. It calls `test.yml`, then builds and
smoke-tests reproducible source deployment archives before creating or updating
the matching GitHub Release. The tag, core version, package metadata, built-in
extension manifest, lock file, and CHANGELOG release are validated as a single
version. GitHub Release notes are extracted from that Towncrier-generated
CHANGELOG section.

Release assets:

- `cfms-on-websocket-X.Y.Z.zip`
- `cfms-on-websocket-X.Y.Z.tar.gz`
- `SHA256SUMS.txt`

The archives contain the server, maintenance commands, migrations, configuration
sample, initialization content, and checked-out client CA certificates. Tests,
development tools, repository metadata, local databases, configuration, logs,
credentials, and uploaded content are excluded.

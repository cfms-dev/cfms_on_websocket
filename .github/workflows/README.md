# GitHub Actions Workflows

## test.yml - Automated Testing

This workflow runs the pytest test suite automatically when:
- Code is pushed to any branch
- A pull request is opened or updated
- Another workflow calls it as a reusable test gate

### What it does:
1. Sets up a Python 3.14 environment
2. Installs project dependencies and test requirements
3. Creates necessary directories for the server
4. Runs the full test suite with pytest
5. Uploads test results and logs as artifacts (retained for 7 days)

### Configuration:
- **Timeout**: 10 minutes per test run
- **Python version**: Tests run on Python 3.14
- **Artifacts**: Test cache and server logs are uploaded for debugging

### Viewing Results:
- Check the "Actions" tab in the GitHub repository
- Test results will show pass/fail status for each Python version
- Download artifacts to review detailed logs if tests fail

## release.yml - Deployment Bundles

This workflow runs when a stable `vX.Y.Z` tag is pushed. The tag must match
`project.version` in `pyproject.toml`. It calls `test.yml`, then builds and
smoke-tests reproducible source deployment archives before creating or updating
the matching GitHub Release.

Release assets:

- `cfms-on-websocket-X.Y.Z.zip`
- `cfms-on-websocket-X.Y.Z.tar.gz`
- `SHA256SUMS.txt`

The archives contain the server, maintenance commands, migrations, configuration
sample, initialization content, and checked-out client CA certificates. Tests,
development tools, repository metadata, local databases, configuration, logs,
credentials, and uploaded content are excluded.

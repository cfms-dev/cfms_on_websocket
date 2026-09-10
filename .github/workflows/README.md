# GitHub Actions Workflows

## test.yml - Automated Testing

This workflow runs the pytest test suite automatically when:
- Code is pushed to any branch
- A pull request is opened or updated
- A release needs tests for a commit without an existing test run

Pushes and pull requests do not start this workflow when every changed file is
Markdown, is under `docs/`, `changelog.d/`, `.codex/`, or `.vscode/`, or is the
root `.gitignore`. A change to any other file starts the full workflow, including
when documentation and source changes are mixed. Calls from `release.yml` are
never path-filtered.

Do not make this path-filtered workflow a required status check: GitHub leaves a
required check pending when its workflow is skipped by path filtering. If a
required test check is introduced, replace the event-level filter with a
lightweight required job and conditionally skip only the expensive test jobs.

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
`project.version` in `pyproject.toml`. Before publishing, it looks for a
successful `test.yml` run for the exact tagged commit. It reuses that result (or
waits for the run if it is still in progress) instead of running the same test
suite again. The release briefly waits for a simultaneously pushed branch run
to be registered. If no run exists, it calls `test.yml` once as a fallback; an
existing successful run takes precedence, while only failed or cancelled runs
stop the release instead of being hidden by a retry.

After the test gate passes, the workflow builds and smoke-tests reproducible
source deployment archives before creating or updating the matching GitHub
Release. The tag, core version, package metadata, built-in extension manifest,
lock file, and CHANGELOG release are validated as a single version. GitHub
Release notes are extracted from that Towncrier-generated CHANGELOG section.

Release assets:

- `cfms-on-websocket-X.Y.Z.zip`
- `cfms-on-websocket-X.Y.Z.tar.gz`
- `SHA256SUMS.txt`

The archives contain the server, maintenance commands, migrations, configuration
sample, initialization content, and checked-out client CA certificates. Tests,
development tools, repository metadata, local databases, configuration, logs,
credentials, and uploaded content are excluded.

## performance.yml - Manual Performance Comparison

This workflow is available only through `workflow_dispatch`. It does not run on
pushes or pull requests and is not part of ordinary pytest.

Required dispatch inputs select the baseline and candidate refs, load profile,
target/environment, repetition count, relative regression threshold, and a
project-owner supplied label for a fixed self-hosted performance runner. A
generic `self-hosted` label is rejected because strict comparisons require a
known, otherwise-idle machine rather than an arbitrary runner.

The current workflow supports only `managed-disposable` on
`local-disposable`. It uses `tools/run_performance_comparison.py` to create
temporary linked worktrees, apply one harness revision to both server refs, run
matching random seeds sequentially, and compare median results. It uploads raw
JSON, the comparison report, the orchestration manifest, harness output, and
service logs for 30 days.

No deployment command, remote address, runner label, or Secret name is assumed
by the repository. Before adding a remote target, a project owner must define
those infrastructure contracts and update both the orchestrator and
`docs/PERFORMANCE_TESTING.md`. GitHub-hosted runners may be useful for checking
that orchestration starts, but their variable performance must not be used as a
strict regression gate.

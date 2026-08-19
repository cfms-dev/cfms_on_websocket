# CFMS on WebSocket

CFMS (Confidential File Management System), is a complete solution for 
managing confidential documents. This is the repository used to 
implement server functionality.

The Project is still in the early stages of development and cannot 
guarantee the security and stability of running the Service. 

Welcome to Github Issues for improvements and bug reports.

You can access the Chinese Simplified version of the development 
documentation here: [CFMS Server Documentation][doc-url].

Note that the documentation may be incomplete or outdated, so don't 
forget to check the source code for verification.

[doc-url]: https://cfms-server-doc.readthedocs.io/zh_CN/latest

## Quick Setup

```bash
# Clone repo
git clone https://github.com/cfms-dev/cfms_on_websocket.git

# Enter working dir
cd cfms_on_websocket/src

# Setup submodules
git submodule init
git submodule update --depth=1

# Setup dependencies
uv sync --upgrade

# Activate virtual environment
source .venv/bin/activate
```

## Optional Dependencies

CFMS has some optional features that require additional dependencies to be 
installed to enable them. For example, the following command will install 
the necessary dependencies for cluster functionality and MySQL support:

```bash
uv sync --extra cluster --extra mysql
```

## Deploy a Release Bundle

Release tags publish source deployment bundles in both ZIP and tar.gz formats.
The deployment host must provide Python 3.14 or newer and
[uv](https://docs.astral.sh/uv/). Verify the downloaded files against
`SHA256SUMS.txt`, then extract the format appropriate for the host:

```bash
sha256sum --check SHA256SUMS.txt
tar -xzf cfms-on-websocket-0.5.0.tar.gz
cd cfms-on-websocket-0.5.0
```

Install only the locked production dependencies. Add `--extra cluster`,
`--extra mysql`, or `--extra ext_oidc_sso` when those features are required:

```bash
uv sync --locked --no-dev
cd src
cp config.toml.sample config.toml  # first installation only
uv run --no-dev alembic upgrade head
uv run --no-dev python main.py  # DO NOT use `-O`!
```

For an upgrade, back up the deployment first and retain the existing
`config.toml`, database, `content` directory, certificates, and credentials.
The release bundle intentionally contains none of that mutable or sensitive
state; do not replace it with sample or empty content from a new bundle.

## Extensions

Extensions are discovered through versioned `manifest.toml` files and are
enabled by identifier in `config.toml`. See the [extension guide](docs/EXTENSIONS.md)
for the manifest schema, activation rules, and migration instructions.

## Configuration Maintenance

After updating CFMS, run the template synchronization command from `src` to add
new settings, migrate known legacy settings, and review settings that no longer
appear in `config.toml.sample`:

```bash
maintain config sync-template
```

The command uses the new template's layout and comments while retaining current
values for settings that still exist. Extension-owned and local settings are not
treated as obsolete automatically: the interactive workflow asks about each one,
and `--yes` preserves them. For unattended upgrades, use repeated `--remove`
options for selected paths or `--prune` to remove every template-external path.
Use `--check` to report drift without writing files.

Before replacing `config.toml`, the command validates the merged document,
creates a timestamped `config.toml.backup-*` copy, and performs an atomic
replacement. A running server can reload most changes, but settings documented as
restart-only, including extension activation, still require a restart. Protect the
backup files as carefully as `config.toml` because they contain the previous
credentials and secrets.

## Run
```bash
python main.py # DO NOT use `-O`!
```

## Database Migrations
The structure of the database varies between different server versions. In order 
to allow server operators to upgrade to latest versions easily, here, we use 
Alembic to handle database migrations.

**Note:** 
1. Remember to backup your databases in advance to avoid data losses.

2. Configs and generated revisions in `/src/include/alembic/versions/` of 
Alembic is designed for sqlite databases, and we don't guarantee that other types 
of databases can be successfully upgraded via these revisions.

3. Document and directory names share one namespace within each directory.
Active names must be unique; soft-deleted items release their names. The database
migration stops before making schema changes if it finds historical duplicate
names or invalid parent links, so resolve the reported records and retry. The old
`document.allow_name_duplicate` option is ignored.

If you have not used Alembic yet, please run the command below **before** you 
checkout new changes:

```bash
alembic stamp head
```

Then checkout the server version you wanted and run:

```bash
alembic upgrade head 
``` 

## Development

Consider using pre-commit to provide an automated code standardization experience.

```bash
# Install development dependencies
uv sync --dev

# Install pre-commit hooks
uv run pre-commit install
```

Regarding policy, different sections of the codebase are subject to varying 
management approaches for AI-generated code, while the project as a whole accepts AI 
contributions: 

1. Components critical to core logic (that is, the code located in the `include` 
directory) require human review to ensure adherence to human-friendly coding standards; 
2. Tests and maintenance tools are currently written and reviewed entirely by AI, 
meaning we guarantee only the correctness of their output rather than their internal 
execution logic.

## Testing

This repository includes an automated test suite built with pytest. Note that
you should finish the installation before running tests.

To run the tests:

```bash
# Install dependencies
uv sync --dev

# Run all tests
uv run pytest

# Run specific test files
uv run pytest tests/test_basic.py
```

For more information about the test suite, see [tests/README.md](tests/README.md).

## Security

We do our utmost to prevent and resolve security issues within our capabilities. 
If you discover any existing vulnerabilities, you are welcome to submit a report 
to us.

## Contributing

This is a project that is under active development and we are looking 
for people interested in the project to participate in testing. We are 
well aware that the system still has huge shortcomings as a functional 
solution – and we want as many people as possible to join in improving 
them.

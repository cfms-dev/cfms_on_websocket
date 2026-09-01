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

By default, this server-side component runs on SQLite and requires no additional database engine support.

> [!IMPORTANT]
> Differences in implementation and configuration across various database engines may lead to variations in certain behaviors of this server-side implementation. 
> 
> For example, if you want to maintain case sensitivity for usernames, filenames, and directory names in MySQL—consistent with SQLite—you should consider setting `collation-server = utf8mb4_0900_bin`.

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
tar -xzf cfms-on-websocket-0.6.0.tar.gz
cd cfms-on-websocket-0.6.0
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
for the manifest schema, activation rules, package format, and migration
instructions. From the server's `src` directory, `maintain extension` can list,
inspect, install, upgrade, enable, disable, and uninstall local extension ZIP
packages. These commands do not execute extension code or install its Python
dependencies, and activation changes require a server restart.

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

## Audit Log Maintenance

Administrators can preview, selectively export, and archive old audit entries
before deleting them with the `maintain audit` commands. See the
[audit log maintenance guide](docs/AUDIT_LOG_MAINTENANCE.md) for retention,
filtering, archive-safety, and recovery details.

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

### Migrating Between SQLite and MySQL

The maintenance CLI can clone a stopped server database between SQLite and MySQL
8.4.x or 9.7.x LTS. The source must already be at the current Alembic head, and
the target database must contain no tables. The command migrates and verifies all
application tables, including transfer tasks, throttles, deduplication work,
and persisted system state. It does not copy file storage or other providers.

Install the MySQL driver on any host that connects to MySQL:

```bash
uv sync --locked --extra mysql
```

Create a separate target TOML file. It may be a complete CFMS configuration or
contain only the target database table:

```toml
[database]
type = "mysql"
host = "mysql.example.net"
port = 3306
username = "cfms"
password = "replace-with-a-secret"
name = "app_db"
charset = "utf8mb4"
```

MySQL 9.7 uses `caching_sha2_password` by default and no longer provides
`mysql_native_password`. Ensure the configured database account uses
`caching_sha2_password`; Connector/Python in the locked environment supports it.

Stop CFMS, retain a source backup, and run the migration from `src`:

```bash
maintain database migrate --target-config config.mysql.toml
```

The source remains unchanged. By default, successful migration does not edit
`config.toml`; update it manually after reviewing the result. To make the same
successful migration perform an atomic, backed-up switch, include `--activate`
in the initial command:

```bash
maintain database migrate --target-config config.mysql.toml --activate
```

`--activate` changes only the database table in `config.toml` and prints the
backup path. Restart CFMS after activation. Use `--yes` only for unattended
runs where the server-stop and empty-target preconditions have already been
enforced. If copying or verification fails, the tool keeps the source intact
and attempts to return the initially empty target schema to an empty state.

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

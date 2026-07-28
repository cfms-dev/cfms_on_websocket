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

## Extensions

Extensions are discovered through versioned `manifest.toml` files and are
enabled by identifier in `config.toml`. See the [extension guide](docs/EXTENSIONS.md)
for the manifest schema, activation rules, and migration instructions.

## Document Upload Lifecycle

Document upload reservations expire if transfer does not start in time. Once an
upload is claimed, it receives a separate hard deadline and is also subject to
an inactivity timeout. Abandoned initial uploads are purged so their document
names become available again. Per-creator reservation limits and per-account and
per-IP creation limits protect the namespace from abuse. Download task issuance
and transfer starts have an independent adaptive policy that defaults to
observation mode; bearer credentials and resumable downloads remain supported.

Deleting a document cancels transfers only when the underlying file is no longer
reachable from another active document, a user avatar, or an extension-owned
foreign-key reference. See the
[document upload lifecycle guide](docs/DOCUMENT_UPLOAD_LIFECYCLE.md) for states,
client errors, configuration, and upgrade behavior.

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

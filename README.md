# CFMS on WebSocket

CFMS on WebSocket is the server-side implementation of the Confidential File
Management System (CFMS) protocol.

> [!WARNING]
> This project is still under active development and does not yet guarantee
> production-grade security or stability.

For design and API documentation, see the
[Simplified Chinese documentation][documentation]. Note that the documentation 
may be incomplete or outdated, so don't forget to check the source code for 
verification.

## Quick Start

CFMS requires Python 3.14 or newer and [uv](https://docs.astral.sh/uv/). SQLite
is used by default, so no separate database service is required.

> [!IMPORTANT]
> Differences in implementation and configuration across various database engines 
may lead to variations in certain behaviors of this server-side implementation. 
> 
> For example, if you want to maintain case sensitivity for usernames, filenames, 
and directory names in MySQL—consistent with SQLite—you should consider setting 
`collation-server = utf8mb4_0900_bin`.

```bash
git clone --recurse-submodules https://github.com/cfms-dev/cfms_on_websocket.git
cd cfms_on_websocket
uv sync --locked
cp src/config.toml.sample src/config.toml
uv run python src/main.py  # Do not use Python's -O option.
```

On Windows PowerShell, replace `cp` with `Copy-Item`.

## Optional Features

Install the matching extra when using cluster support or an external database:

```bash
uv sync --locked --extra cluster
uv sync --locked --extra mysql
uv sync --locked --extra postgresql
```

Distributed scheduling also requires `--extra ext-scheduling-cluster`. See the
[scheduling guide](docs/SCHEDULING.md) for details.

## Maintenance

The `maintain` command covers release-bundle deployment, configuration updates,
database migrations, audit logs, and extensions:

```bash
uv run maintain --help
```

More detailed guides are available for
[extensions](docs/EXTENSIONS.md),
[audit log queries](docs/AUDIT_LOG_API.md), and
[audit log maintenance](docs/AUDIT_LOG_MAINTENANCE.md).

## Development

```bash
uv sync --dev
uv run pre-commit install
uv run pytest
```

See [tests/README.md](tests/README.md) for test-suite details.

AI-generated contributions are accepted. Changes to core logic under
`src/include` require human review; tests and maintenance tools are evaluated by
their externally observable correctness.

## Contributing and Security

Bug reports, improvement proposals, and testing contributions are welcome through
[GitHub Issues](https://github.com/cfms-dev/cfms_on_websocket/issues). Please
follow [SECURITY.md](SECURITY.md) when reporting a vulnerability.

[documentation]: https://cfms-server-doc.readthedocs.io/zh_CN/latest

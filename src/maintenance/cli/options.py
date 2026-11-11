from pathlib import Path
from typing import Annotated, Any

import typer
from rich.table import Table

import maintenance.operations.config.options as operations
from maintenance.cli.common import _run, console
lazy from include.config.options import ResolvedOption
lazy from include.database.options import StoredOption

app = typer.Typer(
    help="Read and update database-backed settings.", no_args_is_help=True
)


def _print_option(option: ResolvedOption[Any] | StoredOption) -> None:
    console.print_json(
        data={
            "namespace": option.namespace,
            "owner": option.owner,
            "option_key": option.option_key,
            "schema_version": option.schema_version,
            "revision": option.revision,
            "value": option.value,
            "updated_at": option.updated_at,
        }
    )


@app.command("list")
def list_options(
    namespace: Annotated[str | None, typer.Option("--namespace")] = None,
) -> None:
    """List stored settings, including owners whose extension is not installed."""
    options = _run(lambda: operations.list_options(namespace))
    table = Table(title="Configuration Settings")
    for column in ("Namespace", "Key", "Schema", "Revision", "Source"):
        table.add_column(column)
    for option in options:
        table.add_row(
            option.namespace,
            option.option_key,
            str(option.schema_version),
            str(option.revision),
            "Database" if option.revision else "Default",
        )
    console.print(table)


@app.command("get")
def get_options(namespace: str, option_key: str) -> None:
    """Print a stored setting and its revision without importing its namespace."""
    _print_option(_run(lambda: operations.get_options(namespace, option_key)))


@app.command("set")
def set_options(
    namespace: str,
    option_key: str,
    payload_file: Annotated[
        Path, typer.Argument(exists=True, dir_okay=False, resolve_path=True)
    ],
    expected_revision: Annotated[int, typer.Option("--expected-revision", min=0)],
) -> None:
    """Set one value from a JSON file; revision zero creates a missing row."""
    _print_option(
        _run(
            lambda: operations.set_options(
                namespace,
                option_key,
                payload_file,
                expected_revision=expected_revision,
            )
        )
    )


@app.command("set-many")
def set_many_options(
    namespace: str,
    payload_file: Annotated[
        Path, typer.Argument(exists=True, dir_okay=False, resolve_path=True)
    ],
) -> None:
    """Atomically update entries containing value and expected_revision from JSON."""
    options = _run(lambda: operations.set_many_options(namespace, payload_file))
    console.print_json(
        data={
            key: {
                "value": option.value,
                "schema_version": option.schema_version,
                "revision": option.revision,
                "updated_at": option.updated_at,
            }
            for key, option in options.items()
        }
    )


@app.command("reset")
def reset_options(
    namespace: str,
    option_key: str,
    expected_revision: Annotated[int, typer.Option("--expected-revision", min=0)],
) -> None:
    """Persist this setting's code default using its expected revision."""
    _print_option(
        _run(
            lambda: operations.reset_options(
                namespace,
                option_key,
                expected_revision=expected_revision,
            )
        )
    )

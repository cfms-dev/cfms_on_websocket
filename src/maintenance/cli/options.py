from pathlib import Path
from typing import Annotated, Any

import typer
from rich.table import Table

import maintenance.operations.config.options as operations
from maintenance.cli.common import _run, console
lazy from include.config.options import ResolvedOption
lazy from include.database.options import StoredOption

app = typer.Typer(
    help="Read and update database-backed configuration groups.", no_args_is_help=True
)


def _print_option(option: ResolvedOption[Any] | StoredOption) -> None:
    console.print_json(
        data={
            "owner": option.owner,
            "option_key": option.option_key,
            "schema_version": option.schema_version,
            "revision": option.revision,
            "payload": option.payload,
            "updated_at": option.updated_at,
        }
    )


@app.command("list")
def list_options(owner: Annotated[str | None, typer.Option("--owner")] = None) -> None:
    """List stored groups, including owners whose extension is not installed."""
    options = _run(lambda: operations.list_options(owner))
    table = Table(title="Configuration Groups")
    for column in ("Owner", "Key", "Schema", "Revision", "Source"):
        table.add_column(column)
    for option in options:
        table.add_row(
            option.owner,
            option.option_key,
            str(option.schema_version),
            str(option.revision),
            "Database" if option.revision else "Default",
        )
    console.print(table)


@app.command("get")
def get_options(owner: str, option_key: str) -> None:
    """Print a stored configuration group and its revision without importing its owner."""
    _print_option(_run(lambda: operations.get_options(owner, option_key)))


@app.command("set")
def set_options(
    owner: str,
    option_key: str,
    payload_file: Annotated[
        Path, typer.Argument(exists=True, dir_okay=False, resolve_path=True)
    ],
    expected_revision: Annotated[int, typer.Option("--expected-revision", min=0)],
) -> None:
    """Replace a complete group from JSON; revision zero creates a missing row."""
    _print_option(
        _run(
            lambda: operations.set_options(
                owner,
                option_key,
                payload_file,
                expected_revision=expected_revision,
            )
        )
    )


@app.command("reset")
def reset_options(
    owner: str,
    option_key: str,
    expected_revision: Annotated[int, typer.Option("--expected-revision", min=0)],
) -> None:
    """Persist code defaults using the expected revision, without deleting the row."""
    _print_option(
        _run(
            lambda: operations.reset_options(
                owner,
                option_key,
                expected_revision=expected_revision,
            )
        )
    )

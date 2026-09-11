from pathlib import Path
from typing import Annotated

import typer
from rich.table import Table

import maintenance.operations.database as operations
from maintenance.cli.common import (
    VerboseOption,
    _build_backup_progress,
    _configure_logging,
    _confirm_or_abort,
    _run,
    console,
)

app = typer.Typer(
    help="Maintain databases.",
    rich_markup_mode="rich",
    no_args_is_help=True,
)


@app.command(
    "upgrade",
)
def upgrade_database(
    yes: Annotated[
        bool,
        typer.Option(
            "--yes",
            help="Confirm that the CFMS server is stopped.",
        ),
    ] = False,
    verbose: VerboseOption = False,
) -> None:
    """Upgrade the configured database schema to this release's head."""

    _configure_logging(verbose)
    _confirm_or_abort("The CFMS server must be stopped. Continue?", yes)
    result = _run(
        operations.upgrade_database,
        status="Upgrading database schema...",
    )
    table = Table(title="Database Schema Upgrade", show_header=False)
    table.add_column("Field", style="cyan")
    table.add_column("Value", style="green")
    table.add_row("Previous revision", result.previous_revision or "unversioned")
    table.add_row("Current revision", result.current_revision)
    table.add_row("Fresh bootstrap", "Yes" if result.bootstrapped else "No")
    console.print(table)


@app.command(
    "migrate",
    no_args_is_help=True,
    epilog=(
        "Example:\n"
        "  maintain database migrate --target-config config.mysql.toml "
        "--activate --yes"
    ),
)
def migrate_database(
    target_config_path: Annotated[
        Path,
        typer.Option(
            "--target-config",
            help="TOML file containing the target database settings.",
            resolve_path=True,
        ),
    ],
    activate: Annotated[
        bool,
        typer.Option(
            "--activate",
            help="Back up config.toml and switch it to the verified target.",
        ),
    ] = False,
    yes: Annotated[
        bool,
        typer.Option(
            "--yes",
            help="Confirm that the server is stopped and the target is disposable.",
        ),
    ] = False,
    verbose: VerboseOption = False,
) -> None:
    """Clone the stopped server database into an empty database engine."""

    _configure_logging(verbose)
    _confirm_or_abort(
        "The CFMS server must be stopped. The target database must be empty and "
        "will be cleaned if migration fails. Continue?",
        yes,
    )
    with _build_backup_progress() as progress:
        result = _run(
            lambda: operations.migrate_database(
                target_config_path,
                activate=activate,
                progress=progress,
            )
        )

    table = Table(title="Database Migration", show_header=False)
    table.add_column("Field", style="cyan")
    table.add_column("Value", style="green")
    table.add_row("Source", result.source_dialect)
    table.add_row("Target", result.target_dialect)
    table.add_row("Migrated tables", str(result.table_count))
    table.add_row("Migrated rows", str(result.row_count))
    table.add_row("Elapsed", f"{result.elapsed_seconds:.2f} seconds")
    table.add_row("Target config", str(result.target_config_path))
    if result.config_backup_path is not None:
        table.add_row("Previous config backup", str(result.config_backup_path))
        table.add_row("Activation", "config.toml updated; restart required")
    else:
        table.add_row("Activation", "not requested")
    console.print(table)

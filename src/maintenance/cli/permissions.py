from typing import Annotated

import typer
from rich.table import Table

import maintenance.operations.permissions as operations
from maintenance.cli.common import (
    _confirm_or_abort,
    _print_success,
    _run,
    console,
)

app = typer.Typer(
    help="Maintain permission entries.",
    rich_markup_mode="rich",
    no_args_is_help=True,
)


def _print_permission_purge_result(
    result: operations.PermissionPurgeResult,
    *,
    title: str,
) -> None:
    table = Table(title=title, show_header=False)
    table.add_column("Field", style="cyan")
    table.add_column("Value", style="green")
    table.add_row("Cutoff timestamp", str(result.cutoff))
    table.add_row("User permission entries", str(result.user_entries))
    table.add_row("Group permission entries", str(result.group_entries))
    table.add_row("Total", str(result.total))
    console.print(table)


@app.command("purge-expired")
def purge_expired_permissions(
    dry_run: Annotated[
        bool,
        typer.Option("--dry-run", help="Show eligible entries without deleting them."),
    ] = False,
    yes: Annotated[
        bool,
        typer.Option("--yes", help="Skip confirmation before permanent deletion."),
    ] = False,
) -> None:
    """Purge permission entries older than the configured retention period."""

    preview = _run(
        operations.inspect_expired_permissions,
        status="Inspecting expired permission entries...",
    )
    _print_permission_purge_result(preview, title="Expired Permission Entries")
    if dry_run:
        return
    if preview.total == 0:
        _print_success("No expired permission entries are eligible for deletion.")
        return

    entry_label = "entry" if preview.total == 1 else "entries"
    _confirm_or_abort(
        f"Permanently delete {preview.total} expired permission {entry_label}?",
        yes,
    )
    result = _run(
        lambda: operations.purge_expired_permissions(preview.cutoff),
        status="Purging expired permission entries...",
    )
    _print_permission_purge_result(result, title="Purged Permission Entries")

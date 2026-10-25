from typing import Annotated

import typer
from rich.table import Table

import maintenance.operations.permissions as operations
from include.domains.identity.default_groups import DEFAULT_GROUP_PERMISSIONS
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


def _print_default_group_permission_diff(
    result: operations.DefaultGroupPermissionDiff,
) -> None:
    table = Table(title="Default Group Permission Records")
    table.add_column("Group", style="cyan")
    table.add_column("Defaults", justify="right")
    table.add_column("Recorded", justify="right")
    table.add_column("Missing permissions")
    for group_name in result.group_names:
        recorded = sum(group == group_name for group, _ in result.existing_permissions)
        missing = sorted(
            permission
            for group, permission in result.missing_permissions
            if group == group_name
        )
        table.add_row(
            group_name,
            str(len(DEFAULT_GROUP_PERMISSIONS[group_name])),
            str(recorded),
            "Group missing; skipped"
            if group_name in result.missing_groups
            else "\n".join(missing) or "—",
        )
    console.print(table)
    console.print("Recorded permissions may be revoked, expired, or not yet active.")


@app.command("sync-defaults")
def sync_default_permissions(
    group: Annotated[
        list[str] | None,
        typer.Option(
            "--group",
            help="Select a default group; may be repeated. Defaults to all default groups.",
        ),
    ] = None,
    dry_run: Annotated[
        bool,
        typer.Option("--dry-run", help="Show missing records without inserting them."),
    ] = False,
    yes: Annotated[
        bool,
        typer.Option("--yes", help="Skip confirmation before adding missing records."),
    ] = False,
) -> None:
    """Restore missing default group permission records. Stop all servers before writing."""
    unknown_groups = set(group or ()) - DEFAULT_GROUP_PERMISSIONS.keys()
    if unknown_groups:
        raise typer.BadParameter(
            f"Unknown default groups: {', '.join(sorted(unknown_groups))}. "
            f"Choose from: {', '.join(DEFAULT_GROUP_PERMISSIONS)}.",
            param_hint="--group",
        )

    preview = _run(
        lambda: operations.inspect_default_group_permissions(group),
        status="Inspecting default group permission records...",
    )
    _print_default_group_permission_diff(preview)
    if dry_run:
        return
    if not preview.missing_permissions:
        _print_success(
            "No permission records need to be added to existing default groups."
        )
        return

    _confirm_or_abort(
        f"Add {len(preview.missing_permissions)} missing default permission records? "
        "All servers sharing this database must be stopped",
        yes,
    )
    added = _run(
        lambda: operations.sync_default_group_permissions(preview),
        status="Adding missing default group permission records...",
    )
    _print_success(f"Added {added} default group permission records.")

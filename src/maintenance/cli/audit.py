import datetime as dt
from pathlib import Path
from typing import Annotated

import typer
from rich.panel import Panel
from rich.table import Table

import maintenance.operations.audit as operations
from maintenance.cli.common import (
    _confirm_or_abort,
    _print_success,
    _run,
    console,
)

app = typer.Typer(
    help="Maintain audit log entries.",
    rich_markup_mode="rich",
    no_args_is_help=True,
)


def _parse_audit_before(value: str | None) -> dt.datetime | None:
    if value is None:
        return None
    normalized = f"{value[:-1]}+00:00" if value.endswith("Z") else value
    try:
        parsed = dt.datetime.fromisoformat(normalized)
    except ValueError as exc:
        raise typer.BadParameter(
            "--before must be an ISO 8601 timestamp with a timezone offset."
        ) from exc
    if parsed.tzinfo is None or parsed.utcoffset() is None:
        raise typer.BadParameter("--before must include a timezone offset.")
    return parsed


def _create_audit_selection(
    *,
    before: str | None,
    actions: list[str] | None,
    usernames: list[str] | None,
    targets: list[str] | None,
    results: list[int] | None,
    remote_addresses: list[str] | None,
) -> operations.AuditSelection:
    parsed_before = _parse_audit_before(before)
    return _run(
        lambda: operations.create_audit_selection(
            before=parsed_before,
            actions=actions or (),
            usernames=usernames or (),
            targets=targets or (),
            results=results or (),
            remote_addresses=remote_addresses or (),
        )
    )


def _format_audit_cutoff(cutoff: float) -> str:
    return dt.datetime.fromtimestamp(cutoff, dt.UTC).isoformat()


def _print_audit_inspection(result: operations.AuditInspectionResult) -> None:
    summary = Table(title="Eligible Audit Entries", show_header=False)
    summary.add_column("Field", style="cyan")
    summary.add_column("Value", style="green")
    summary.add_row("Cutoff", _format_audit_cutoff(result.selection.cutoff))
    summary.add_row("Total", str(result.total))
    console.print(summary)

    if result.action_counts:
        actions = Table(title="Entries by Action")
        actions.add_column("Action", style="cyan")
        actions.add_column("Count", style="green", justify="right")
        for action, count in result.action_counts:
            actions.add_row(action, str(count))
        console.print(actions)

    if result.result_counts:
        results = Table(title="Entries by Result")
        results.add_column("Result", style="cyan")
        results.add_column("Count", style="green", justify="right")
        for result_code, count in result.result_counts:
            results.add_row(str(result_code), str(count))
        console.print(results)


def _print_audit_export_result(result: operations.AuditExportResult) -> None:
    table = Table(title="Audit Export", show_header=False)
    table.add_column("Field", style="cyan")
    table.add_column("Value", style="green")
    table.add_row("Output", str(result.output_path))
    table.add_row("Cutoff", _format_audit_cutoff(result.selection.cutoff))
    table.add_row("Records", str(result.record_count))
    console.print(table)
    console.print(
        Panel(
            "This readable JSONL file may contain usernames, IP addresses, "
            "targets, and operation details. Store it securely.",
            title="Sensitive audit data",
            border_style="yellow",
        )
    )


@app.command("export", no_args_is_help=True)
def export_audit_logs(
    output_path: Annotated[
        Path,
        typer.Argument(
            help="Where the readable JSONL export should be written.",
            resolve_path=True,
        ),
    ],
    before: Annotated[
        str | None,
        typer.Option(
            "--before",
            help="Only include entries before this timezone-aware ISO 8601 time.",
        ),
    ] = None,
    actions: Annotated[
        list[str] | None,
        typer.Option("--action", help="Include one action; may be repeated."),
    ] = None,
    usernames: Annotated[
        list[str] | None,
        typer.Option("--username", help="Include one username; may be repeated."),
    ] = None,
    targets: Annotated[
        list[str] | None,
        typer.Option("--target", help="Include one target; may be repeated."),
    ] = None,
    results: Annotated[
        list[int] | None,
        typer.Option(
            "--result", help="Include one exact result code; may be repeated."
        ),
    ] = None,
    remote_addresses: Annotated[
        list[str] | None,
        typer.Option(
            "--remote-address",
            help="Include one remote address; may be repeated.",
        ),
    ] = None,
) -> None:
    """Export selected expired audit entries as readable JSONL."""

    selection = _create_audit_selection(
        before=before,
        actions=actions,
        usernames=usernames,
        targets=targets,
        results=results,
        remote_addresses=remote_addresses,
    )
    result = _run(
        lambda: operations.export_audit_entries(output_path, selection),
        status="Exporting eligible audit entries...",
    )
    _print_audit_export_result(result)


@app.command("purge")
def purge_audit_logs(
    archive_path: Annotated[
        Path | None,
        typer.Option(
            "--archive",
            help="JSONL path that must be written successfully before deletion.",
            resolve_path=True,
        ),
    ] = None,
    before: Annotated[
        str | None,
        typer.Option(
            "--before",
            help="Only include entries before this timezone-aware ISO 8601 time.",
        ),
    ] = None,
    actions: Annotated[
        list[str] | None,
        typer.Option("--action", help="Include one action; may be repeated."),
    ] = None,
    usernames: Annotated[
        list[str] | None,
        typer.Option("--username", help="Include one username; may be repeated."),
    ] = None,
    targets: Annotated[
        list[str] | None,
        typer.Option("--target", help="Include one target; may be repeated."),
    ] = None,
    results: Annotated[
        list[int] | None,
        typer.Option(
            "--result", help="Include one exact result code; may be repeated."
        ),
    ] = None,
    remote_addresses: Annotated[
        list[str] | None,
        typer.Option(
            "--remote-address",
            help="Include one remote address; may be repeated.",
        ),
    ] = None,
    dry_run: Annotated[
        bool,
        typer.Option(
            "--dry-run", help="Show eligible entries without writing or deleting."
        ),
    ] = False,
    yes: Annotated[
        bool,
        typer.Option("--yes", help="Skip confirmation before permanent deletion."),
    ] = False,
) -> None:
    """Archive and then purge selected expired audit entries."""

    if not dry_run and archive_path is None:
        raise typer.BadParameter("--archive is required unless --dry-run is used.")

    selection = _create_audit_selection(
        before=before,
        actions=actions,
        usernames=usernames,
        targets=targets,
        results=results,
        remote_addresses=remote_addresses,
    )
    inspection = _run(
        lambda: operations.inspect_audit_entries(selection),
        status="Inspecting eligible audit entries...",
    )
    _print_audit_inspection(inspection)
    if dry_run:
        return
    if inspection.total == 0:
        _print_success("No audit entries are eligible for deletion.")
        return

    _confirm_or_abort(
        f"Archive and permanently delete {inspection.total} audit entries?",
        yes,
    )
    result = _run(
        lambda: operations.purge_audit_entries(
            archive_path,
            selection,
            expected_count=inspection.total,
        ),
        status="Archiving and purging eligible audit entries...",
    )
    table = Table(title="Purged Audit Entries", show_header=False)
    table.add_column("Field", style="cyan")
    table.add_column("Value", style="green")
    table.add_row("Archive", str(result.archive_path))
    table.add_row("Cutoff", _format_audit_cutoff(result.selection.cutoff))
    table.add_row("Archived", str(result.archived_count))
    table.add_row("Deleted", str(result.deleted_count))
    console.print(table)
    console.print(
        Panel(
            "The archive contains sensitive audit data. Store it securely.",
            title="Sensitive audit data",
            border_style="yellow",
        )
    )

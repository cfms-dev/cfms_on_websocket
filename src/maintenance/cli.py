import datetime as dt
import logging
from collections.abc import Callable
from pathlib import Path
from typing import Annotated

import typer
from rich.console import Console
from rich.logging import RichHandler
from rich.panel import Panel
from rich.progress import (
    BarColumn,
    MofNCompleteColumn,
    Progress,
    SpinnerColumn,
    TextColumn,
    TimeElapsedColumn,
)
from rich.prompt import Confirm, Prompt
from rich.table import Column, Table

from maintenance import operations
from maintenance.runtime import MaintenanceRuntimeError

console = Console()
error_console = Console(stderr=True)
_LOG_HANDLER_MARKER = "_cfms_maintenance_cli_handler"
_INTERACTIVE_BACKUP_COMPONENTS = (
    (
        "accounts",
        "Accounts, groups, permissions, keyrings, and user block rules",
        True,
    ),
    (
        "documents",
        "Document library, directories, revisions, metadata, and access rules",
        True,
    ),
    ("audit", "Audit log entries", True),
    ("banned_subnets", "Banned network subnets", True),
    ("configuration", "Configuration secrets needed by restored servers", True),
)
_INTERACTIVE_COMPONENT_DEPENDENCIES = {
    "documents": ("accounts",),
    "audit": ("accounts",),
}
VerboseOption = Annotated[
    bool,
    typer.Option(
        "--verbose",
        "-v",
        help="Show detailed diagnostic logs.",
    ),
]


app = typer.Typer(
    help="CFMS maintenance command line tools.",
    rich_markup_mode="rich",
    no_args_is_help=True,
)
user_app = typer.Typer(
    help="Maintain users.",
    rich_markup_mode="rich",
    no_args_is_help=True,
)
config_app = typer.Typer(
    help="Maintain configuration.",
    rich_markup_mode="rich",
    no_args_is_help=True,
)
backup_app = typer.Typer(
    help="Maintain backups.",
    rich_markup_mode="rich",
    no_args_is_help=True,
)
audit_app = typer.Typer(
    help="Maintain audit log entries.",
    rich_markup_mode="rich",
    no_args_is_help=True,
)
permission_app = typer.Typer(
    help="Maintain permission entries.",
    rich_markup_mode="rich",
    no_args_is_help=True,
)
database_app = typer.Typer(
    help="Maintain databases.",
    rich_markup_mode="rich",
    no_args_is_help=True,
)
extension_app = typer.Typer(
    help="Manage server extensions.",
    rich_markup_mode="rich",
    no_args_is_help=True,
)

app.add_typer(user_app, name="user")
app.add_typer(config_app, name="config")
app.add_typer(backup_app, name="backup")
app.add_typer(audit_app, name="audit")
app.add_typer(permission_app, name="permission")
app.add_typer(database_app, name="database")
app.add_typer(extension_app, name="extension")


def _run[T](action: Callable[[], T], *, status: str | None = None) -> T:
    try:
        if status is None:
            return action()
        with console.status(status, spinner="dots"):
            return action()
    except (MaintenanceRuntimeError, operations.MaintenanceOperationError) as exc:
        _print_error(str(exc))
        raise typer.Exit(1) from exc


def _print_error(message: str) -> None:
    error_console.print(
        Panel(
            message,
            title="Maintenance command failed",
            border_style="red",
        )
    )


def _print_success(message: str) -> None:
    console.print(Panel(message, title="Done", border_style="green"))


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


@audit_app.command("export", no_args_is_help=True)
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


@audit_app.command("purge")
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


@permission_app.command("purge-expired")
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


def _configure_logging(verbose: bool) -> None:
    logger = logging.getLogger("maintenance")
    for handler in list(logger.handlers):
        if getattr(handler, _LOG_HANDLER_MARKER, False):
            logger.removeHandler(handler)

    if not verbose:
        logger.setLevel(logging.WARNING)
        logger.propagate = True
        return

    handler = RichHandler(
        console=error_console,
        markup=False,
        rich_tracebacks=False,
        show_path=False,
    )
    setattr(handler, _LOG_HANDLER_MARKER, True)
    handler.setLevel(logging.DEBUG)
    logger.addHandler(handler)
    logger.setLevel(logging.DEBUG)
    logger.propagate = False


def _build_backup_progress() -> Progress:
    return Progress(
        SpinnerColumn(),
        TextColumn(
            "{task.description}",
            markup=False,
            table_column=Column(ratio=1, no_wrap=True, overflow="ellipsis"),
        ),
        BarColumn(),
        MofNCompleteColumn(),
        TimeElapsedColumn(),
        console=error_console,
    )


@database_app.command(
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


def _confirm_or_abort(message: str, yes: bool) -> None:
    if yes:
        return
    typer.confirm(message, abort=True)


def _extension_dependency_text(record: operations.ExtensionRecord) -> str:
    dependencies = record.manifest.dependencies.extensions
    if not dependencies:
        return "-"
    return ", ".join(
        f"{identifier}>={version}" for identifier, version in dependencies.items()
    )


def _extension_health_text(record: operations.ExtensionRecord) -> str:
    return "; ".join(record.issues) if record.issues else "Healthy"


def _print_extension_record(record: operations.ExtensionRecord) -> None:
    metadata = record.manifest.extension
    table = Table(title="Server Extension", show_header=False)
    table.add_column("Field", style="cyan", no_wrap=True)
    table.add_column("Value")
    table.add_row("Identifier", metadata.identifier)
    table.add_row("Name", metadata.name)
    table.add_row("Version", metadata.version)
    table.add_row("Manifest", str(record.manifest.manifest_version))
    table.add_row("Authors", ", ".join(metadata.authors))
    table.add_row("License", metadata.license)
    table.add_row("Description", metadata.description or "-")
    table.add_row("Homepage", metadata.homepage or "-")
    minimum = record.manifest.compatibility.minimum_server_version
    table.add_row("Minimum server", str(minimum) if minimum is not None else "-")
    table.add_row("Compatible", "Yes" if record.compatible else "No")
    table.add_row("Enabled", "Yes" if record.enabled else "No")
    table.add_row("Dependencies", _extension_dependency_text(record))
    table.add_row("Health", _extension_health_text(record))
    table.add_row("Directory", str(record.directory))
    console.print(table)


def _print_extension_change(result: operations.ExtensionChangeResult) -> None:
    _print_extension_record(result.extension)
    table = Table(title="Planned Changes", show_header=False)
    table.add_column("Field", style="cyan", no_wrap=True)
    table.add_column("Value")
    table.add_row("Action", result.action)
    if result.package_path is not None:
        table.add_row("Package", str(result.package_path))
    if result.package_sha256 is not None:
        table.add_row("SHA-256", result.package_sha256)
    table.add_row("Enable", ", ".join(result.enabled_added) or "-")
    table.add_row("Disable", ", ".join(result.enabled_removed) or "-")
    table.add_row("Changes required", "Yes" if result.changed else "No")
    console.print(table)
    if result.package_path is not None:
        console.print(
            Panel(
                "Extension packages contain trusted Python code. SHA-256 verifies "
                "integrity only; it does not authenticate the publisher.",
                title="Extension Code Warning",
                border_style="yellow",
            )
        )


def _extension_success_message(
    message: str, result: operations.ExtensionChangeResult, *, restart: bool
) -> str:
    details = [message]
    if result.config_backup_path is not None:
        details.append(f"Configuration backup: {result.config_backup_path}")
    if restart:
        details.append("Restart any running server for the change to take effect.")
    return "\n".join(details)


@extension_app.command("list")
def list_extensions() -> None:
    """List installed extensions and their activation health."""
    inspection = _run(
        operations.inspect_extensions,
        status="Inspecting installed extensions...",
    )
    table = Table(title="Installed Server Extensions")
    table.add_column("Identifier", style="cyan", no_wrap=True)
    table.add_column("Name")
    table.add_column("Version", no_wrap=True)
    table.add_column("Enabled", no_wrap=True)
    table.add_column("Compatible", no_wrap=True)
    table.add_column("Health", ratio=2)
    details = Table(title="Extension Dependencies and Locations")
    details.add_column("Identifier", style="cyan", no_wrap=True)
    details.add_column("Dependencies", ratio=2)
    details.add_column("Directory", ratio=3, overflow="fold")
    for record in inspection.extensions:
        metadata = record.manifest.extension
        table.add_row(
            metadata.identifier,
            metadata.name,
            metadata.version,
            "Yes" if record.enabled else "No",
            "Yes" if record.compatible else "No",
            _extension_health_text(record),
        )
        details.add_row(
            metadata.identifier,
            _extension_dependency_text(record),
            str(record.directory),
        )
    console.print(table)
    console.print(details)
    if inspection.activation_error is not None:
        error_console.print(
            Panel(
                inspection.activation_error,
                title="Extension Activation Is Invalid",
                border_style="red",
            )
        )
        raise typer.Exit(1)


@extension_app.command("info")
def extension_info(
    identifier: Annotated[str, typer.Argument(help="Installed extension identifier.")],
) -> None:
    """Show the manifest and current state of one installed extension."""
    record = _run(
        lambda: operations.inspect_extension(identifier),
        status="Inspecting extension...",
    )
    _print_extension_record(record)


@extension_app.command("install")
def install_extension(
    package: Annotated[
        Path,
        typer.Argument(help="Local extension ZIP package.", resolve_path=True),
    ],
    sha256: Annotated[
        str | None,
        typer.Option("--sha256", help="Expected package SHA-256 digest."),
    ] = None,
    yes: Annotated[
        bool,
        typer.Option("--yes", help="Install without interactive confirmation."),
    ] = False,
) -> None:
    """Install a local extension package without enabling it."""
    preview = _run(
        lambda: operations.install_extension(
            package, expected_sha256=sha256, write=False
        ),
        status="Validating extension package...",
    )
    _print_extension_change(preview)
    _confirm_or_abort("Install this extension package?", yes)
    result = _run(
        lambda: operations.install_extension(
            package,
            expected_sha256=preview.package_sha256,
            write=True,
        ),
        status="Installing extension...",
    )
    _print_success(
        _extension_success_message(
            f"Installed {result.extension.manifest.extension.identifier!r}. "
            "The extension remains disabled.",
            result,
            restart=False,
        )
    )


@extension_app.command("upgrade")
def upgrade_extension(
    package: Annotated[
        Path,
        typer.Argument(help="Local extension ZIP package.", resolve_path=True),
    ],
    sha256: Annotated[
        str | None,
        typer.Option("--sha256", help="Expected package SHA-256 digest."),
    ] = None,
    yes: Annotated[
        bool,
        typer.Option("--yes", help="Upgrade without interactive confirmation."),
    ] = False,
) -> None:
    """Replace an installed extension with a strictly newer version."""
    preview = _run(
        lambda: operations.upgrade_extension(
            package, expected_sha256=sha256, write=False
        ),
        status="Validating extension upgrade...",
    )
    _print_extension_change(preview)
    _confirm_or_abort("Apply this extension upgrade?", yes)
    result = _run(
        lambda: operations.upgrade_extension(
            package,
            expected_sha256=preview.package_sha256,
            write=True,
        ),
        status="Upgrading extension...",
    )
    _print_success(
        _extension_success_message(
            f"Upgraded {result.extension.manifest.extension.identifier!r} to "
            f"{result.extension.manifest.extension.version}.",
            result,
            restart=True,
        )
    )


@extension_app.command("enable")
def enable_extension(
    identifier: Annotated[str, typer.Argument(help="Installed extension identifier.")],
    yes: Annotated[
        bool,
        typer.Option("--yes", help="Enable without interactive confirmation."),
    ] = False,
) -> None:
    """Enable an extension and its installed dependencies."""
    preview = _run(lambda: operations.enable_extension(identifier, write=False))
    _print_extension_change(preview)
    if not preview.changed:
        _print_success(f"Extension {identifier!r} is already enabled.")
        return
    _confirm_or_abort("Apply these extension activation changes?", yes)
    result = _run(
        lambda: operations.enable_extension(identifier, write=True),
        status="Updating extension activation...",
    )
    _print_success(
        _extension_success_message(f"Enabled {identifier!r}.", result, restart=True)
    )


@extension_app.command("disable")
def disable_extension(
    identifier: Annotated[str, typer.Argument(help="Installed extension identifier.")],
    yes: Annotated[
        bool,
        typer.Option("--yes", help="Disable without interactive confirmation."),
    ] = False,
) -> None:
    """Disable an extension and its enabled dependents."""
    preview = _run(lambda: operations.disable_extension(identifier, write=False))
    _print_extension_change(preview)
    if not preview.changed:
        _print_success(f"Extension {identifier!r} is already disabled.")
        return
    _confirm_or_abort("Apply these extension activation changes?", yes)
    result = _run(
        lambda: operations.disable_extension(identifier, write=True),
        status="Updating extension activation...",
    )
    _print_success(
        _extension_success_message(f"Disabled {identifier!r}.", result, restart=True)
    )


@extension_app.command("uninstall")
def uninstall_extension(
    identifier: Annotated[str, typer.Argument(help="Installed extension identifier.")],
    yes: Annotated[
        bool,
        typer.Option("--yes", help="Uninstall without interactive confirmation."),
    ] = False,
) -> None:
    """Remove extension code while preserving its configuration and runtime state."""
    preview = _run(lambda: operations.uninstall_extension(identifier, write=False))
    _print_extension_change(preview)
    _confirm_or_abort("Uninstall this extension and apply linked disables?", yes)
    result = _run(
        lambda: operations.uninstall_extension(identifier, write=True),
        status="Uninstalling extension...",
    )
    _print_success(
        _extension_success_message(
            f"Uninstalled {identifier!r}; extension configuration and runtime "
            "state were preserved.",
            result,
            restart=True,
        )
    )


@user_app.command(
    "reset-password",
    no_args_is_help=True,
    epilog="Example: maintain user reset-password alice --password NewPass123!",
)
def reset_password(
    username: Annotated[
        str,
        typer.Argument(help="Account whose password should be reset."),
    ],
    password: Annotated[
        str | None,
        typer.Option(
            "--password",
            metavar="NEW_PASSWORD",
            help="New password. A secure password is generated when omitted.",
        ),
    ] = None,
) -> None:
    """Reset a user's password."""

    result = _run(
        lambda: operations.reset_password(username, password),
        status="Resetting password...",
    )

    if result.generated_password is None:
        _print_success(f"Password for {result.username!r} has been updated.")
        return

    table = Table(title="Generated Password", show_header=True)
    table.add_column("Username", style="cyan")
    table.add_column("Password", style="yellow")
    table.add_row(result.username, result.generated_password)
    console.print(table)
    console.print(
        "[bold yellow]Store this password safely. It will not be shown again.[/]"
    )


@user_app.command(
    "clear-totp",
    no_args_is_help=True,
    epilog=(
        "Examples:\n"
        "  maintain user clear-totp alice\n"
        "  maintain user clear-totp --all --yes"
    ),
)
def clear_totp(
    username: Annotated[
        str | None,
        typer.Argument(help="Username whose TOTP state should be cleared."),
    ] = None,
    all_users: Annotated[
        bool,
        typer.Option("--all", help="Clear TOTP state for every user."),
    ] = False,
    yes: Annotated[
        bool,
        typer.Option("--yes", help="Skip confirmation for high-risk operations."),
    ] = False,
) -> None:
    """Clear TOTP state for one user or all users."""

    if all_users == bool(username):
        raise typer.BadParameter(
            "Choose exactly one TOTP target: provide a username or pass --all.\n\n"
            "Examples:\n"
            "  maintain user clear-totp alice\n"
            "  maintain user clear-totp --all --yes",
        )

    if all_users:
        _confirm_or_abort("Clear TOTP state for every user?", yes)

    result = _run(
        lambda: operations.clear_totp(username, all_users=all_users),
        status="Clearing TOTP state...",
    )

    if result.username is None:
        _print_success(f"Cleared TOTP state for {result.updated_count} user(s).")
    else:
        _print_success(f"Cleared TOTP state for user {result.username!r}.")


@config_app.command("fill-pepper")
def fill_pepper() -> None:
    """Generate and store a security pepper when missing."""

    result = _run(operations.fill_pepper, status="Inspecting config.toml...")

    if result.changed:
        _print_success(f"Generated and stored pepper in {result.config_path}.")
    else:
        _print_success(f"Pepper is already set in {result.config_path}.")


def _print_config_sync_result(result: operations.ConfigSyncResult) -> None:
    table = Table(title="Configuration Template Sync")
    table.add_column("Change", style="cyan", no_wrap=True)
    table.add_column("Configuration path")
    for path in result.added_paths:
        table.add_row("Add", path)
    for migration in result.migrations:
        table.add_row("Migrate", migration)
    for path in result.removed_paths:
        table.add_row("Remove", path)
    for path in result.preserved_paths:
        table.add_row("Preserve", path)
    if (
        result.added_paths
        or result.migrations
        or result.removed_paths
        or result.preserved_paths
    ):
        console.print(table)

    if result.warnings:
        console.print(
            Panel(
                "\n".join(result.warnings),
                title="Configuration Warnings",
                border_style="yellow",
            )
        )


@config_app.command(
    "sync-template",
    epilog=(
        "Examples:\n"
        "  maintain config sync-template\n"
        "  maintain config sync-template --check\n"
        "  maintain config sync-template --yes --remove server.old_setting"
    ),
)
def sync_config_template(
    template_path: Annotated[
        Path | None,
        typer.Option(
            "--template",
            help="Configuration template to merge into config.toml.",
            resolve_path=True,
            show_default="config.toml.sample",
        ),
    ] = None,
    check: Annotated[
        bool,
        typer.Option(
            "--check",
            help="Report whether synchronization is needed without writing files.",
        ),
    ] = False,
    yes: Annotated[
        bool,
        typer.Option(
            "--yes",
            help="Apply known changes without interactive confirmation.",
        ),
    ] = False,
    remove: Annotated[
        list[str] | None,
        typer.Option(
            "--remove",
            help="Remove one template-external path; may be repeated.",
        ),
    ] = None,
    prune: Annotated[
        bool,
        typer.Option(
            "--prune",
            help="Remove every template-external path.",
        ),
    ] = False,
) -> None:
    """Merge new template settings and migrate or remove obsolete settings."""

    remove_paths = set(remove or ())
    if prune and remove_paths:
        raise typer.BadParameter("--prune cannot be combined with --remove.")
    if check and yes:
        raise typer.BadParameter("--check cannot be combined with --yes.")
    if template_path is None:
        template_path = Path("config.toml.sample")

    inspection = _run(
        lambda: operations.inspect_config_template(template_path),
        status="Inspecting configuration documents...",
    )
    if not check and not yes and not prune:
        for path in inspection.unknown_paths:
            if path in remove_paths:
                continue
            if typer.confirm(
                f"Remove template-external configuration path {path!r}?",
                default=False,
            ):
                remove_paths.add(path)

    preview = _run(
        lambda: operations.sync_config_template(
            template_path,
            remove_paths=tuple(sorted(remove_paths)),
            prune=prune,
            write=False,
        ),
        status="Preparing configuration changes...",
    )
    _print_config_sync_result(preview)

    if check:
        if preview.changed:
            raise typer.Exit(1)
        _print_success("config.toml is synchronized with the template.")
        return
    if not preview.changed:
        _print_success("config.toml is already synchronized with the template.")
        return

    _confirm_or_abort(
        "Back up config.toml and apply these configuration changes?",
        yes,
    )
    result = _run(
        lambda: operations.sync_config_template(
            template_path,
            remove_paths=tuple(sorted(remove_paths)),
            prune=prune,
            write=True,
        ),
        status="Backing up and updating config.toml...",
    )
    if result.backup_path is None:
        _print_success("config.toml is already synchronized with the template.")
        return
    _print_success(f"Synchronized {result.config_path}. Backup: {result.backup_path}")


@backup_app.command(
    "export",
    no_args_is_help=True,
    epilog="Example: maintain backup export backup.confbak --key-out backup.key",
)
def export_backup(
    output_path: Annotated[
        Path | None,
        typer.Argument(
            help="Where the encrypted backup should be written.",
            resolve_path=True,
        ),
    ] = None,
    key_output_path: Annotated[
        Path | None,
        typer.Option(
            "--key-out",
            help="File to receive the generated key.",
            resolve_path=True,
        ),
    ] = None,
    interactive: Annotated[
        bool,
        typer.Option(
            "--interactive",
            "-i",
            help="Run an interactive backup export wizard.",
        ),
    ] = False,
    verbose: VerboseOption = False,
) -> None:
    """Export an encrypted CFMS backup."""

    if interactive:
        if output_path is not None or key_output_path is not None or verbose:
            raise typer.BadParameter(
                "Interactive export must be invoked as "
                "`maintain backup export -i` without other arguments or options."
            )
        _run_interactive_backup_export()
        return
    if output_path is None:
        raise typer.BadParameter(
            "Where the encrypted backup should be written.\n\n"
            "Examples:\n"
            "  maintain backup export backup.confbak --key-out backup.key\n"
            "  maintain backup export -i"
        )

    _configure_logging(verbose)
    with _build_backup_progress() as progress:
        result = _run(
            lambda: operations.export_backup(
                output_path,
                key_output_path=key_output_path,
                progress=progress,
                show_progress_details=verbose,
            ),
        )

    _print_backup_export_result(result)


def _print_backup_export_result(
    result: operations.BackupExportResult,
    *,
    show_key: bool | None = None,
) -> None:
    if show_key is None:
        show_key = result.key_output_path is None

    table = Table(title="Backup Export", show_header=False)
    table.add_column("Field", style="cyan")
    table.add_column("Value", style="green")
    table.add_row("Backup", str(result.output_path))
    if result.key_output_path is not None:
        table.add_row("Key file", str(result.key_output_path))
    if show_key:
        table.add_row("Decryption key", result.key)
    console.print(table)
    _print_backup_warnings(result.warnings)
    if show_key:
        console.print(
            "[bold yellow]Store this key safely. "
            "It is required to import the backup.[/]"
        )


def _run_interactive_backup_export() -> None:
    _configure_logging(False)
    console.print(Panel("Interactive backup export", title="Backup Wizard"))
    components, added_components = _prompt_backup_components()
    output_path = Path(
        Prompt.ask(
            "Backup output path",
            default="backup.confbak",
            console=console,
        )
    ).resolve()
    key_mode = Prompt.ask(
        "Key output",
        choices=["terminal", "file", "both"],
        default="terminal",
        console=console,
    )
    key_output_path = None
    if key_mode in {"file", "both"}:
        default_key_path = str(output_path.with_suffix(".key"))
        key_output_path = Path(
            Prompt.ask(
                "Key output path",
                default=default_key_path,
                console=console,
            )
        ).resolve()

    _print_interactive_backup_summary(
        components,
        added_components=added_components,
        output_path=output_path,
        key_output_path=key_output_path,
        key_mode=key_mode,
    )
    if not Confirm.ask(
        "Export backup with these settings?",
        default=True,
        console=console,
    ):
        raise typer.Abort()

    with _build_backup_progress() as progress:
        result = _run(
            lambda: operations.export_backup(
                output_path,
                key_output_path=key_output_path,
                components=components,
                progress=progress,
                show_progress_details=False,
            ),
        )
    _print_backup_export_result(result, show_key=key_mode in {"terminal", "both"})


def _prompt_backup_components() -> tuple[tuple[str, ...], tuple[str, ...]]:
    selected: set[str] = set()
    table = Table(title="Backup Components", show_header=True)
    table.add_column("Component", style="cyan")
    table.add_column("Included data", style="green")
    for component, description, _default in _INTERACTIVE_BACKUP_COMPONENTS:
        table.add_row(component, description)
    console.print(table)

    for component, description, default in _INTERACTIVE_BACKUP_COMPONENTS:
        if Confirm.ask(f"Export {description}?", default=default, console=console):
            selected.add(component)
    if not selected:
        raise typer.BadParameter("Choose at least one backup component.")

    explicit = set(selected)
    selected = _resolve_interactive_backup_components(selected)
    added = tuple(sorted(selected - explicit))
    if added:
        console.print(
            Panel(
                ", ".join(added),
                title="Automatically Included Dependencies",
                border_style="yellow",
            )
        )
    return tuple(sorted(selected)), added


def _resolve_interactive_backup_components(components: set[str]) -> set[str]:
    resolved = set(components)
    changed = True
    while changed:
        changed = False
        for component in tuple(resolved):
            for dependency in _INTERACTIVE_COMPONENT_DEPENDENCIES.get(component, ()):
                if dependency not in resolved:
                    resolved.add(dependency)
                    changed = True
    return resolved


def _print_interactive_backup_summary(
    components: tuple[str, ...],
    *,
    added_components: tuple[str, ...],
    output_path: Path,
    key_output_path: Path | None,
    key_mode: str,
) -> None:
    summary = Table(title="Backup Export Summary", show_header=False)
    summary.add_column("Field", style="cyan")
    summary.add_column("Value", style="green")
    summary.add_row("Components", ", ".join(components))
    if added_components:
        summary.add_row("Auto-included", ", ".join(added_components))
    summary.add_row("Backup", str(output_path))
    summary.add_row("Key output", key_mode)
    if key_output_path is not None:
        summary.add_row("Key file", str(key_output_path))
    console.print(summary)


def _print_backup_warnings(warnings: tuple[str, ...]) -> None:
    if not warnings:
        return
    console.print(
        Panel(
            "\n".join(warnings),
            title="Skipped Files",
            border_style="yellow",
        )
    )


@backup_app.command(
    "info",
    no_args_is_help=True,
    epilog="Example: maintain backup info backup.confbak",
)
def backup_info(
    backup_path: Annotated[
        Path,
        typer.Argument(help="Backup file to inspect.", resolve_path=True),
    ],
    verbose: VerboseOption = False,
) -> None:
    """Show unencrypted backup header information."""

    _configure_logging(verbose)
    header = _run(
        lambda: operations.read_backup_info(backup_path),
        status="Reading backup header...",
    )

    table = Table(title="CFMS Backup", show_header=False)
    table.add_column("Field", style="cyan")
    table.add_column("Value", style="green")
    table.add_row("Format version", str(header.format_version))
    table.add_row("Created at", header.created_at)
    table.add_row("Core version", header.core_version)
    table.add_row("Compression", header.compression)
    table.add_row("Encryption", header.encryption)
    console.print(table)


@backup_app.command(
    "import",
    no_args_is_help=True,
    epilog=(
        "Examples:\n"
        "  maintain backup import backup.confbak --key-file backup.key --yes\n"
        "  maintain backup import backup.confbak --key <base64url-key> --yes"
    ),
)
def import_backup(
    backup_path: Annotated[
        Path,
        typer.Argument(help="Backup file to import.", resolve_path=True),
    ],
    key: Annotated[
        str | None,
        typer.Option("--key", help="Base64url decryption key."),
    ] = None,
    key_file_path: Annotated[
        Path | None,
        typer.Option(
            "--key-file",
            help="File containing the decryption key.",
            resolve_path=True,
        ),
    ] = None,
    yes: Annotated[
        bool,
        typer.Option("--yes", help="Skip confirmation for high-risk operations."),
    ] = False,
    verbose: VerboseOption = False,
) -> None:
    """Import an encrypted CFMS backup into an empty database."""

    _configure_logging(verbose)
    if (key is None) == (key_file_path is None):
        raise typer.BadParameter(
            "Choose exactly one decryption key source: pass --key or --key-file.\n\n"
            "Examples:\n"
            "  maintain backup import backup.confbak --key-file backup.key --yes\n"
            "  maintain backup import backup.confbak --key <base64url-key> --yes",
        )

    _confirm_or_abort(
        "Importing a backup will write database rows, storage files, "
        "and config keys. Continue?",
        yes,
    )
    with _build_backup_progress() as progress:
        result = _run(
            lambda: operations.import_backup(
                backup_path,
                key=key,
                key_file=key_file_path,
                progress=progress,
                show_progress_details=verbose,
            ),
        )

    table = Table(title="Backup Import", show_header=False)
    table.add_column("Field", style="cyan")
    table.add_column("Value", style="green")
    table.add_row("Created at", result.created_at)
    table.add_row("Source core version", result.core_version)
    table.add_row("Restored tables", str(result.table_count))
    table.add_row("Restored files", str(result.file_count))
    console.print(table)


if __name__ == "__main__":
    app()

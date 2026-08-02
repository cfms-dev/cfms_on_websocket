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

app.add_typer(user_app, name="user")
app.add_typer(config_app, name="config")
app.add_typer(backup_app, name="backup")


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


def _confirm_or_abort(message: str, yes: bool) -> None:
    if yes:
        return
    typer.confirm(message, abort=True)


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
        Path,
        typer.Option(
            "--template",
            help="Configuration template to merge into config.toml.",
        ),
    ] = Path("config.toml.sample"),
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
        typer.Argument(help="Where the encrypted backup should be written."),
    ] = None,
    key_output_path: Annotated[
        Path | None,
        typer.Option("--key-out", help="File to receive the generated key."),
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
    )
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
        )

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
    backup_path: Annotated[Path, typer.Argument(help="Backup file to inspect.")],
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
    backup_path: Annotated[Path, typer.Argument(help="Backup file to import.")],
    key: Annotated[
        str | None,
        typer.Option("--key", help="Base64url decryption key."),
    ] = None,
    key_file_path: Annotated[
        Path | None,
        typer.Option("--key-file", help="File containing the decryption key."),
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

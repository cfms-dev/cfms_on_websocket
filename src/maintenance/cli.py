from __future__ import annotations

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
from rich.table import Table

from maintenance import operations
from maintenance.runtime import MaintenanceRuntimeError

console = Console()
error_console = Console(stderr=True)
_LOG_HANDLER_MARKER = "_cfms_maintenance_cli_handler"
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
        TextColumn("{task.description}", markup=False),
        BarColumn(),
        MofNCompleteColumn(),
        TimeElapsedColumn(),
        console=console,
    )


def _confirm_or_exit(message: str, yes: bool) -> None:
    if yes:
        return
    if not typer.confirm(message):
        raise typer.Exit(1)


def _parameter_error(message: str) -> None:
    raise typer.BadParameter(message)


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
        _parameter_error(
            "Choose exactly one TOTP target: provide a username or pass --all.\n\n"
            "Examples:\n"
            "  maintain user clear-totp alice\n"
            "  maintain user clear-totp --all --yes",
        )

    if all_users:
        _confirm_or_exit("Clear TOTP state for every user?", yes)

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


@backup_app.command(
    "export",
    no_args_is_help=True,
    epilog="Example: maintain backup export backup.confbak --key-out backup.key",
)
def export_backup(
    output_path: Annotated[
        Path,
        typer.Argument(help="Where the encrypted backup should be written."),
    ],
    key_output_path: Annotated[
        Path | None,
        typer.Option("--key-out", help="File to receive the generated key."),
    ] = None,
    verbose: VerboseOption = False,
) -> None:
    """Export an encrypted CFMS backup."""

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

    table = Table(title="Backup Export", show_header=False)
    table.add_column("Field", style="cyan")
    table.add_column("Value", style="green")
    table.add_row("Backup", str(result.output_path))
    if result.key_output_path is None:
        table.add_row("Decryption key", result.key)
        console.print(table)
        _print_backup_warnings(result.warnings)
        console.print(
            "[bold yellow]Store this key safely. "
            "It is required to import the backup.[/]"
        )
    else:
        table.add_row("Key file", str(result.key_output_path))
        console.print(table)
        _print_backup_warnings(result.warnings)


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
        _parameter_error(
            "Choose exactly one decryption key source: pass --key or --key-file.\n\n"
            "Examples:\n"
            "  maintain backup import backup.confbak --key-file backup.key --yes\n"
            "  maintain backup import backup.confbak --key <base64url-key> --yes",
        )

    _confirm_or_exit(
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

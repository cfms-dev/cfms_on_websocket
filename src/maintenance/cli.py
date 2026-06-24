from __future__ import annotations

from collections.abc import Callable
from pathlib import Path
from typing import Annotated, ClassVar

import typer
from rich.console import Console
from rich.panel import Panel
from rich.table import Table
from typer.core import TyperCommand
from typer.core import _click as click

from maintenance import operations
from maintenance.runtime import MaintenanceRuntimeError

console = Console()
error_console = Console(stderr=True)


class HelpfulUsageCommand(TyperCommand):
    argument_hints: ClassVar[dict[str, str]] = {}
    option_value_hints: ClassVar[dict[str, str]] = {}

    def parse_args(self, ctx: click.Context, args: list[str]) -> list[str]:
        try:
            return super().parse_args(ctx, args)
        except click.exceptions.MissingParameter as exc:
            hint = self._missing_parameter_hint(exc)
            if hint is None:
                raise
            raise click.exceptions.UsageError(
                f"{exc.format_message()}\n\n{hint}",
                ctx,
            ) from exc
        except click.exceptions.BadOptionUsage as exc:
            hint = self.option_value_hints.get(exc.option_name)
            if hint is None:
                raise
            raise click.exceptions.UsageError(
                f"{exc.format_message()}\n\n{hint}",
                ctx,
            ) from exc

    def _missing_parameter_hint(
        self,
        exc: click.exceptions.MissingParameter,
    ) -> str | None:
        if exc.param is None or exc.param.name is None:
            return None
        return self.argument_hints.get(exc.param.name)


def _helpful_command(
    *,
    argument_hints: dict[str, str] | None = None,
    option_value_hints: dict[str, str] | None = None,
) -> type[HelpfulUsageCommand]:
    return type(
        "MaintenanceHelpfulUsageCommand",
        (HelpfulUsageCommand,),
        {
            "argument_hints": dict(argument_hints or {}),
            "option_value_hints": dict(option_value_hints or {}),
        },
    )


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


def _confirm_or_exit(message: str, yes: bool) -> None:
    if yes:
        return
    if not typer.confirm(message):
        raise typer.Exit(1)


def _usage_error(ctx: typer.Context, message: str) -> None:
    raise click.exceptions.UsageError(message, ctx)


@user_app.command(
    "reset-password",
    cls=_helpful_command(
        argument_hints={
            "username": (
                "Choose the account whose password should be reset. "
                "Example: maintain user reset-password alice --password NewPass123!"
            ),
        },
        option_value_hints={
            "--password": (
                "Provide the new password after --password, or omit the option "
                "to let maintain generate a secure password."
            ),
        },
    ),
)
def reset_password(
    username: Annotated[str, typer.Argument(help="Username to update.")],
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
    cls=_helpful_command(
        argument_hints={
            "username": (
                "Choose one target user, or use --all to clear TOTP state for "
                "every user. Example: maintain user clear-totp alice"
            ),
        },
    ),
)
def clear_totp(
    ctx: typer.Context,
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
        _usage_error(
            ctx,
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
    cls=_helpful_command(
        argument_hints={
            "output": (
                "Choose where the encrypted backup should be written. "
                "Example: maintain backup export backup.confbak --key-out backup.key"
            ),
        },
        option_value_hints={
            "--key-out": (
                "Provide a file path after --key-out to save the generated "
                "decryption key there."
            ),
        },
    ),
)
def export_backup(
    output: Annotated[Path, typer.Argument(help="Backup file to create.")],
    key_out: Annotated[
        Path | None,
        typer.Option("--key-out", help="File to receive the generated key."),
    ] = None,
) -> None:
    """Export an encrypted CFMS backup."""

    result = _run(
        lambda: operations.export_backup(output, key_output_path=key_out),
        status="Exporting encrypted backup...",
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
    cls=_helpful_command(
        argument_hints={
            "backup": (
                "Provide the backup file to inspect. "
                "Example: maintain backup info backup.confbak"
            ),
        },
    ),
)
def backup_info(
    backup: Annotated[Path, typer.Argument(help="Backup file to inspect.")],
) -> None:
    """Show unencrypted backup header information."""

    header = _run(
        lambda: operations.read_backup_info(backup),
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
    cls=_helpful_command(
        argument_hints={
            "backup": (
                "Provide the encrypted backup file to import, plus exactly one "
                "key source. Example: maintain backup import backup.confbak "
                "--key-file backup.key --yes"
            ),
        },
        option_value_hints={
            "--key": "Provide the base64url decryption key after --key.",
            "--key-file": (
                "Provide the path to a file containing the decryption key after "
                "--key-file."
            ),
        },
    ),
)
def import_backup(
    ctx: typer.Context,
    backup: Annotated[Path, typer.Argument(help="Backup file to import.")],
    key: Annotated[
        str | None,
        typer.Option("--key", help="Base64url decryption key."),
    ] = None,
    key_file: Annotated[
        Path | None,
        typer.Option("--key-file", help="File containing the decryption key."),
    ] = None,
    yes: Annotated[
        bool,
        typer.Option("--yes", help="Skip confirmation for high-risk operations."),
    ] = False,
) -> None:
    """Import an encrypted CFMS backup into an empty database."""

    if (key is None) == (key_file is None):
        _usage_error(
            ctx,
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
    result = _run(
        lambda: operations.import_backup(backup, key=key, key_file=key_file),
        status="Importing encrypted backup...",
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

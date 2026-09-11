from typing import Annotated

import typer
from rich.table import Table

import maintenance.operations.users as operations
from maintenance.cli.common import (
    _confirm_or_abort,
    _print_success,
    _run,
    console,
)

app = typer.Typer(
    help="Maintain users.",
    rich_markup_mode="rich",
    no_args_is_help=True,
)


@app.command(
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


@app.command(
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

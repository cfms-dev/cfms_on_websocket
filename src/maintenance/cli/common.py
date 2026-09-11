import logging
from collections.abc import Callable
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
from rich.table import Column

from maintenance.operations.exceptions import MaintenanceOperationError
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


def _run[T](action: Callable[[], T], *, status: str | None = None) -> T:
    try:
        if status is None:
            return action()
        with console.status(status, spinner="dots"):
            return action()
    except (MaintenanceRuntimeError, MaintenanceOperationError) as exc:
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

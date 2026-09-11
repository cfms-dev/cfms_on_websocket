from pathlib import Path
from typing import Annotated

import typer
from rich.panel import Panel
from rich.table import Table

import maintenance.operations.config as operations
from maintenance.cli.common import (
    _confirm_or_abort,
    _print_success,
    _run,
    console,
)

app = typer.Typer(
    help="Maintain configuration.",
    rich_markup_mode="rich",
    no_args_is_help=True,
)


@app.command("fill-pepper")
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


@app.command(
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

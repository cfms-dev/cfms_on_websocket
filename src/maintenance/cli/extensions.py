from pathlib import Path
from typing import Annotated

import typer
from rich.panel import Panel
from rich.table import Table

import maintenance.operations.extensions as operations
from maintenance.cli.common import (
    _confirm_or_abort,
    _print_success,
    _run,
    console,
    error_console,
)

app = typer.Typer(
    help="Manage server extensions.",
    rich_markup_mode="rich",
    no_args_is_help=True,
)


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


@app.command("list")
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


@app.command("info")
def extension_info(
    identifier: Annotated[str, typer.Argument(help="Installed extension identifier.")],
) -> None:
    """Show the manifest and current state of one installed extension."""
    record = _run(
        lambda: operations.inspect_extension(identifier),
        status="Inspecting extension...",
    )
    _print_extension_record(record)


@app.command("install")
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


@app.command("upgrade")
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


@app.command("enable")
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


@app.command("disable")
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


@app.command("uninstall")
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

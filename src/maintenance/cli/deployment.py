from pathlib import Path
from typing import Annotated

import typer
from rich.table import Table

import maintenance.operations.deployment as operations
from maintenance.cli.common import (
    VerboseOption,
    _configure_logging,
    _confirm_or_abort,
    _print_success,
    _run,
    console,
    error_console,
)

app = typer.Typer(
    help="Check, update, downgrade, inspect, and prune packaged CFMS deployments.",
    rich_markup_mode="rich",
    no_args_is_help=True,
)


def _print_deployment_result(result: operations.DeploymentResult) -> None:
    table = Table(title="CFMS Deployment", show_header=False)
    table.add_column("Field", style="cyan")
    table.add_column("Value", style="green")
    table.add_row("Action", result.action)
    table.add_row("Root", str(result.deployment_root))
    table.add_row("Active version", result.active_version)
    table.add_row("Active release ID", result.active_release_id)
    if result.package_sha256 is not None:
        table.add_row("Package SHA-256", result.package_sha256)
    console.print(table)
    if result.versions:
        _print_deployment_versions("Stored Releases", result.versions)


def _print_deployment_versions(
    title: str,
    versions: tuple[operations.DeploymentVersion, ...],
) -> None:
    table = Table(title=title)
    table.add_column("Version", style="cyan")
    table.add_column("Release ID", style="green")
    table.add_column("Active")
    for release in versions:
        table.add_row(
            release.version,
            release.release_id,
            "Yes" if release.active else "No",
        )
    console.print(table)


def _print_deployment_prune_result(
    result: operations.DeploymentPruneResult,
) -> None:
    table = Table(title="CFMS Deployment Prune", show_header=False)
    table.add_column("Field", style="cyan")
    table.add_column("Value", style="green")
    table.add_row("Root", str(result.deployment_root))
    table.add_row("Active version", result.active_version)
    table.add_row("Active release ID", result.active_release_id)
    table.add_row("Removed releases", str(len(result.removed_versions)))
    console.print(table)
    if result.removed_versions:
        _print_deployment_versions("Pruned Releases", result.removed_versions)


def _print_online_deployment_status(
    result: operations.OnlineDeploymentStatus,
) -> None:
    table = Table(title="CFMS Online Update", show_header=False)
    table.add_column("Field", style="cyan")
    table.add_column("Value", style="green")
    table.add_row("Root", str(result.deployment_root))
    table.add_row("Current version", result.current_version)
    table.add_row("Latest version", result.latest_version)
    if result.update_available:
        update_status = "Available"
    elif result.current_version == result.latest_version:
        update_status = "Up to date"
    else:
        update_status = "Current version is newer"
    table.add_row("Update", update_status)
    table.add_row("Published", result.published_at.isoformat())
    table.add_row("Release", result.release_url)
    console.print(table)


def _deployment_digest_options(
    sha256: str | None,
    checksums: Path | None,
) -> tuple[str | None, Path | None]:
    if sha256 is not None and checksums is not None:
        raise typer.BadParameter("Choose at most one of --sha256 or --checksums.")
    return sha256, checksums


def _resolve_deployment_root(deployment_root: Path | None) -> Path:
    if deployment_root is not None:
        return deployment_root
    current = Path.cwd().resolve()
    for candidate in (current, *current.parents):
        if (candidate / "src" / "main.py").is_file() or (
            candidate / "src" / ".maintenance" / "transaction.json"
        ).is_file():
            return candidate
        if (
            (candidate / "main.py").is_file()
            or (candidate / ".maintenance" / "transaction.json").is_file()
        ) and (candidate.parent / "pyproject.toml").is_file():
            return candidate.parent
    raise typer.BadParameter("Unable to locate a flat CFMS deployment root")


@app.command("upgrade")
def upgrade_deployment(
    package: Annotated[Path, typer.Argument(help="New CFMS release package.")],
    deployment_root: Annotated[
        Path | None,
        typer.Option("--deployment-root", help="Stable deployment directory."),
    ] = None,
    sha256: Annotated[str | None, typer.Option("--sha256")] = None,
    checksums: Annotated[Path | None, typer.Option("--checksums")] = None,
    extra: Annotated[
        list[str] | None,
        typer.Option("--extra", help="Core optional dependency; may be repeated."),
    ] = None,
    requirements_lock: Annotated[
        Path | None,
        typer.Option(
            "--requirements-lock",
            help="Hash-locked requirements for third-party extensions.",
        ),
    ] = None,
    yes: Annotated[bool, typer.Option("--yes")] = False,
    verbose: VerboseOption = False,
) -> None:
    """Stage, migrate, and atomically activate a newer local release."""
    _configure_logging(verbose)
    digest, checksum_file = _deployment_digest_options(sha256, checksums)
    if digest is None and checksum_file is None:
        error_console.print(
            "Warning: external release package SHA-256 verification is disabled; "
            "the embedded release manifest will still be verified.",
            style="yellow",
        )
    resolved_root = _resolve_deployment_root(deployment_root)
    _confirm_or_abort(
        "The server must be stopped. Ensure that a tested, restorable database "
        "checkpoint exists. Upgrade this deployment?",
        yes,
    )
    result = _run(
        lambda: operations.upgrade_deployment(
            package,
            resolved_root,
            expected_sha256=digest,
            checksums_path=checksum_file,
            extras=tuple(extra) if extra is not None else None,
            requirements_lock=requirements_lock,
        ),
        status="Upgrading CFMS deployment...",
    )
    _print_deployment_result(result)


@app.command("status")
def deployment_status(
    deployment_root: Annotated[
        Path | None,
        typer.Option("--deployment-root", help="Stable deployment directory."),
    ] = None,
) -> None:
    """Show the active and stored releases without changing the deployment."""
    _print_deployment_result(
        _run(
            lambda: operations.inspect_deployment(
                _resolve_deployment_root(deployment_root)
            )
        )
    )


@app.command("check")
def check_deployment_update(
    deployment_root: Annotated[
        Path | None,
        typer.Option("--deployment-root", help="Stable deployment directory."),
    ] = None,
) -> None:
    """Check the latest official release without changing the deployment."""
    _print_online_deployment_status(
        _run(
            lambda: operations.inspect_online_deployment(
                _resolve_deployment_root(deployment_root)
            ),
            status="Checking for CFMS updates...",
        )
    )


@app.command("update")
def update_deployment(
    deployment_root: Annotated[
        Path | None,
        typer.Option("--deployment-root", help="Stable deployment directory."),
    ] = None,
    extra: Annotated[
        list[str] | None,
        typer.Option("--extra", help="Core optional dependency; may be repeated."),
    ] = None,
    requirements_lock: Annotated[
        Path | None,
        typer.Option(
            "--requirements-lock",
            help="Hash-locked requirements for third-party extensions.",
        ),
    ] = None,
    yes: Annotated[bool, typer.Option("--yes")] = False,
    verbose: VerboseOption = False,
) -> None:
    """Download and activate the latest official release when newer."""
    _configure_logging(verbose)
    resolved_root = _resolve_deployment_root(deployment_root)
    _confirm_or_abort(
        "The server must be stopped. Ensure that a tested, restorable database "
        "checkpoint exists. Check for and install the latest official release?",
        yes,
    )
    result = _run(
        lambda: operations.update_online_deployment(
            resolved_root,
            extras=tuple(extra) if extra is not None else None,
            requirements_lock=requirements_lock,
        ),
        status="Updating CFMS deployment...",
    )
    _print_online_deployment_status(result.status)
    if result.deployment is not None:
        _print_deployment_result(result.deployment)


@app.command("prune")
def prune_deployment(
    deployment_root: Annotated[
        Path | None,
        typer.Option("--deployment-root", help="Flat release project directory."),
    ] = None,
    dry_run: Annotated[
        bool,
        typer.Option("--dry-run", help="Show inactive releases without deleting them."),
    ] = False,
    yes: Annotated[
        bool,
        typer.Option("--yes", help="Skip confirmation before permanent deletion."),
    ] = False,
) -> None:
    """Permanently remove every inactive stored release."""
    resolved_root = _resolve_deployment_root(deployment_root)
    inspection = _run(lambda: operations.inspect_deployment(resolved_root))
    candidates = tuple(version for version in inspection.versions if not version.active)
    if candidates:
        _print_deployment_versions("Stored Releases to Prune", candidates)
    else:
        _print_success("No inactive stored releases are eligible for pruning.")
        return
    if dry_run:
        return

    _confirm_or_abort(
        "The server must be stopped. Permanently delete these stored releases, "
        "including their code, configuration, and third-party extension snapshots?",
        yes,
    )
    result = _run(
        lambda: operations.prune_deployment(
            resolved_root,
            expected_release_ids=tuple(version.release_id for version in candidates),
        ),
        status="Pruning inactive stored releases...",
    )
    _print_deployment_prune_result(result)


@app.command("downgrade")
def downgrade_deployment(
    release_id: Annotated[
        str,
        typer.Argument(help="Stored release ID or an unambiguous prefix."),
    ],
    deployment_root: Annotated[
        Path | None,
        typer.Option("--deployment-root", help="Flat release project directory."),
    ] = None,
    yes: Annotated[bool, typer.Option("--yes")] = False,
    verbose: VerboseOption = False,
) -> None:
    """Downgrade the database and restore a stored release."""
    _configure_logging(verbose)
    _confirm_or_abort(
        "The server must be stopped. Ensure that a tested, restorable database "
        "checkpoint exists. Downgrade this deployment?",
        yes,
    )
    result = _run(
        lambda: operations.downgrade_deployment(
            release_id,
            _resolve_deployment_root(deployment_root),
        ),
        status="Downgrading CFMS deployment...",
    )
    _print_deployment_result(result)


@app.command("resume")
def resume_deployment(
    deployment_root: Annotated[
        Path | None,
        typer.Option("--deployment-root", help="Flat release project directory."),
    ] = None,
    verbose: VerboseOption = False,
) -> None:
    """Finish or roll back an interrupted deployment transaction."""
    _configure_logging(verbose)
    _print_deployment_result(
        _run(
            lambda: operations.resume_deployment(
                _resolve_deployment_root(deployment_root),
            ),
            status="Recovering CFMS deployment...",
        )
    )

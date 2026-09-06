from pathlib import Path
from typing import Annotated

import typer

app = typer.Typer(
    help="Run distributed CFMS scheduled-task processes.",
    no_args_is_help=True,
)


def _load_runtime(server_root: Path | None):
    from maintenance.runtime import enter_server_root

    resolved_root = enter_server_root(server_root)

    from include.config import paths
    from include.config.settings import global_config
    from include.config.validation import get_enabled_extensions
    from include.extensions.manager import (
        collect_scheduled_tasks,
        load_extensions_from_directory,
    )
    from include.providers.bootstrap import initialize_providers
    from include.providers.manager import ProviderManager
    from include.providers.scheduling.redis import RedisSchedulingProvider

    if global_config["provider"].get("scheduling", "local") != "redis":
        raise typer.BadParameter(
            "cfms-jobs processes require provider.scheduling='redis'"
        )

    import include.database.models  # noqa: F401

    initialize_providers(global_config)
    load_extensions_from_directory(
        paths.EXTENSION_ROOT,
        get_enabled_extensions(global_config),
        config=global_config,
    )
    provider = ProviderManager().scheduling
    if not isinstance(provider, RedisSchedulingProvider):
        raise RuntimeError("Redis scheduling provider was not initialized")
    return resolved_root, provider, collect_scheduled_tasks()


ServerRootOption = Annotated[
    Path | None,
    typer.Option(
        "--server-root",
        help="CFMS server root containing main.py and config.toml.",
        resolve_path=True,
    ),
]


@app.command()
def scheduler(server_root: ServerRootOption = None) -> None:
    """Run a scheduler candidate; Redis elects one active leader."""
    resolved_root, provider, registry = _load_runtime(server_root)
    from include.runtime_lock import jobs_runtime_lock

    with jobs_runtime_lock(resolved_root):
        try:
            provider.run_scheduler(registry)
        finally:
            provider.shutdown()


@app.command()
def worker(server_root: ServerRootOption = None) -> None:
    """Run a Dramatiq worker for scheduled task executions."""
    resolved_root, provider, registry = _load_runtime(server_root)
    from include.runtime_lock import jobs_runtime_lock

    with jobs_runtime_lock(resolved_root):
        try:
            provider.run_worker(registry)
        finally:
            provider.shutdown()

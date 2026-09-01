import os
from pathlib import Path


class MaintenanceRuntimeError(RuntimeError):
    pass


def _activate_server_root(server_root: Path) -> Path:
    try:
        os.chdir(server_root)
    except OSError as exc:
        raise MaintenanceRuntimeError(
            f"Unable to enter the CFMS server root {server_root}: {exc}"
        ) from exc

    from include.config import paths

    paths.SHARED_ROOT_ABSPATH = server_root
    return server_root


def enter_server_root(start: Path | None = None) -> Path:
    configured_root = os.environ.get("CFMS_SERVER_ROOT")
    if configured_root:
        server_root = Path(configured_root).expanduser().resolve()
        if not (server_root / "config.toml").is_file():
            raise MaintenanceRuntimeError(
                f"CFMS_SERVER_ROOT must contain config.toml: {server_root}"
            )
        return _activate_server_root(server_root)

    start_path = (start or Path.cwd()).resolve()
    search_path = (start_path, *start_path.parents)

    server_root = next(
        (
            candidate
            for candidate in search_path
            if (candidate / "main.py").is_file()
            and (candidate / "config.toml").is_file()
        ),
        None,
    )
    if server_root is None:
        server_root = next(
            (
                candidate / "src"
                for candidate in search_path
                if (candidate / "src" / "main.py").is_file()
                and (candidate / "src" / "config.toml").is_file()
            ),
            None,
        )
    if server_root is None:
        server_root = next(
            (
                candidate
                for candidate in search_path
                if (candidate / "config.toml").is_file()
                and (candidate.parent / "deployment.json").is_file()
            ),
            None,
        )
    if server_root is None:
        raise MaintenanceRuntimeError(
            f"Unable to locate a CFMS server root from {start_path}. "
            "A server root must contain main.py and config.toml or be the "
            "shared root of a deployment."
        )

    return _activate_server_root(server_root)


def load_database_models() -> None:
    import include.database.models  # noqa: F401


def initialize_providers() -> None:
    from include.providers.bootstrap import initialize_providers as _initialize

    _initialize()

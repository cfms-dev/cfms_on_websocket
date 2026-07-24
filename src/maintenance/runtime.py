from pathlib import Path


class MaintenanceRuntimeError(RuntimeError):
    pass


def ensure_src_workdir(cwd: Path | None = None) -> Path:
    workdir = (cwd or Path.cwd()).resolve()
    if not (workdir / "config.toml").is_file() or not (workdir / "main.py").is_file():
        raise MaintenanceRuntimeError(
            "Maintenance commands must be run from the CFMS src directory. "
            "Run `cd src` first, then retry the command."
        )
    return workdir


def load_database_models() -> None:
    import include.database.models  # noqa: F401


def initialize_providers() -> None:
    from include.providers.bootstrap import initialize_providers as _initialize

    _initialize()

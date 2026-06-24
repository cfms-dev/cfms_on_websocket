from __future__ import annotations

import importlib
from pathlib import Path


class MaintenanceRuntimeError(RuntimeError):
    pass


MODEL_MODULES = (
    "include.database.models.blocking",
    "include.database.models.classic",
    "include.database.models.entity",
    "include.database.models.file",
    "include.database.models.keyring",
    "include.database.models.security",
)


def ensure_src_workdir(cwd: Path | None = None) -> Path:
    workdir = (cwd or Path.cwd()).resolve()
    if not (workdir / "config.toml").is_file() or not (workdir / "main.py").is_file():
        raise MaintenanceRuntimeError(
            "Maintenance commands must be run from the CFMS src directory. "
            "Run `cd src` first, then retry the command."
        )
    return workdir


def load_database_models() -> None:
    for module_name in MODEL_MODULES:
        importlib.import_module(module_name)


def initialize_providers() -> None:
    from include.providers.bootstrap import initialize_providers as _initialize

    _initialize()

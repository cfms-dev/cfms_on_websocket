"""Absolute paths for packaged application files and mutable server state."""

import os
from pathlib import Path

__all__ = ["APPLICATION_ABSPATH", "EXTENSION_ROOT", "SHARED_ROOT_ABSPATH"]

APPLICATION_ABSPATH = Path(__file__).resolve().parents[2]
EXTENSION_ROOT = APPLICATION_ABSPATH / "include" / "extensions"

_configured_server_root = os.environ.get("CFMS_SERVER_ROOT")
_working_directory = Path.cwd().resolve()
SHARED_ROOT_ABSPATH = (
    Path(_configured_server_root).expanduser().resolve()
    if _configured_server_root
    else (
        _working_directory
        if (_working_directory / "config.toml").is_file()
        else APPLICATION_ABSPATH
    )
)

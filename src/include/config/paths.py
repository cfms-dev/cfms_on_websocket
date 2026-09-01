import os
from pathlib import Path

APPLICATION_ROOT = Path(__file__).resolve().parents[2]

_configured_server_root = os.environ.get("CFMS_SERVER_ROOT")
_working_directory = Path.cwd().resolve()
SERVER_ROOT = (
    Path(_configured_server_root).expanduser().resolve()
    if _configured_server_root
    else (
        _working_directory
        if (_working_directory / "config.toml").is_file()
        else APPLICATION_ROOT
    )
)

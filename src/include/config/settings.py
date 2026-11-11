"""Validated deployment settings, captured at startup without file monitoring."""

import pathlib
import secrets
import threading
from collections.abc import Iterator, Mapping
from typing import Any, Final

from tomlkit import TOMLDocument, dumps, parse

from include.config.legacy_options import legacy_option_paths
from include.config.paths import EXECUTABLE_ABSPATH
from include.config.validation import ConfigValidationError, parse_config_document

__all__ = ["global_config"]


class GlobalConfig(Mapping[str, Any]):
    """Validated startup configuration. File changes require a restart."""

    _initialized = False

    def __new__(cls, *args, **kwargs):
        if not hasattr(cls, "_instance"):
            cls._instance = super().__new__(cls)
        return cls._instance

    def __init__(self, config_path: str = "config.toml"):
        if self._initialized:
            return

        self._config_path = pathlib.Path(config_path).resolve()
        self._data: TOMLDocument
        self._lock = threading.Lock()

        self._load()

        self._initialized = True

    # -- first-run initialization ------------------------------------------

    def initialize_secrets(self) -> None:
        """Generate ``secret_key`` and ``pepper`` on first run.

        Uses ``tomlkit`` to preserve comments and formatting when writing
        back to the config file.  Only runs when the ``init`` sentinel file
        does not exist yet.
        """
        if (self._config_path.parent / "init").exists():
            return

        if not self._config_path.exists():
            raise FileNotFoundError(
                f"Configuration file {self._config_path!r} not found."
            )

        with open(self._config_path, encoding="utf-8") as f:
            toml_doc = parse(f.read())

        changed = False
        for section, key in (("server", "secret_key"), ("security", "pepper")):
            if not toml_doc[section][key]:
                toml_doc[section][key] = secrets.token_hex(32)
                changed = True
        if not changed:
            return

        with open(self._config_path, "w", encoding="utf-8") as f:
            f.write(dumps(toml_doc))

        self._load()

    def require_migrated_options(self) -> None:
        if self._legacy_option_paths:
            raise ConfigValidationError(
                "Database-backed settings remain in config.toml: "
                + ", ".join(self._legacy_option_paths)
                + ". Run 'maintain config migrate-options' before starting the server."
            )

    # -- loading ----------------------------------------------------------

    def _load(self):
        with open(self._config_path, encoding="utf-8") as f:
            new_data = parse_config_document(f.read())

        with self._lock:
            self._data = new_data
            self._legacy_option_paths = legacy_option_paths(new_data)

    # -- dict-like access (thread-safe reads) -----------------------------

    def __getitem__(self, key: str) -> Any:
        with self._lock:
            return self._data[key]

    def __iter__(self) -> Iterator[str]:
        with self._lock:
            return iter(tuple(self._data))

    def __len__(self) -> int:
        with self._lock:
            return len(self._data)

    def __repr__(self):
        with self._lock:
            return (
                f"GlobalConfig(path={self._config_path!r}, "
                f"keys={list(self._data.keys())})"
            )


# Module-level singleton – imported everywhere as `global_config`.
global_config: Final = GlobalConfig(str(EXECUTABLE_ABSPATH / "config.toml"))

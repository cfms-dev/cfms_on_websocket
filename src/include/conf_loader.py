"""include/conf_loader.py

This module loads the global configuration from a TOML file and exposes it
as a thread-safe, dict-like singleton that automatically reloads when the
config file changes on disk.

All parsing and writing is done through ``tomlkit`` so that comments and
formatting are preserved across reloads and write-backs.

The watchdog observer monitors the *directory* containing the config file
rather than the file itself, so that atomic replacements (write-to-temp +
rename, or symlink updates) are detected reliably.
"""

from __future__ import annotations

import os
import pathlib
import secrets
import threading
from typing import Any, Final, overload

from loguru import logger
from tomlkit import TOMLDocument, dumps, parse
from watchdog.events import FileSystemEventHandler
from watchdog.observers import Observer
from watchdog.observers.api import BaseObserver

__all__ = ["global_config"]


class _ConfigEventHandler(FileSystemEventHandler):
    """Watchdog handler that triggers a config reload when the target config
    file (or a symlink to it) changes in the watched directory.

    The directory is watched rather than the file itself so that atomic
    symlink swaps are picked up, but events are filtered to only react to
    changes that affect the config file."""

    def __init__(self, config: GlobalConfig, target_path: pathlib.Path):
        self._config = config
        self._target = target_path.resolve()
        self._debounce_timer: threading.Timer | None = None
        self._debounce_sec = 0.5

    def _is_target(self, event) -> bool:
        try:
            return pathlib.Path(event.src_path).resolve() == self._target
        except OSError:
            return False

    def _schedule_reload(self):
        if self._debounce_timer:
            self._debounce_timer.cancel()
        self._debounce_timer = threading.Timer(self._debounce_sec, self._config.reload)
        self._debounce_timer.daemon = True
        self._debounce_timer.start()

    def on_modified(self, event):
        if event.is_directory or not self._is_target(event):
            return
        self._schedule_reload()

    def on_created(self, event):
        if event.is_directory or not self._is_target(event):
            return
        self._schedule_reload()

    def on_moved(self, event):
        if event.is_directory or not self._is_target(event):
            return
        self._schedule_reload()


class GlobalConfig:
    """Thread-safe global configuration backed by a TOML file.

    Watches the config file's *directory* so that atomic write patterns
    (write-to-temp + rename, symlink swaps) are picked up.  Supports
    dict-like read access for backward compatibility.
    """

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
        self._observer: BaseObserver | None = None

        self._init_secrets()
        self._load()
        self._start_watching()

        self._initialized = True

    # -- first-run initialization ------------------------------------------

    def _init_secrets(self):
        """Generate ``secret_key`` and ``pepper`` on first run.

        Uses ``tomlkit`` to preserve comments and formatting when writing
        back to the config file.  Only runs when the ``init`` sentinel file
        does not exist yet.
        """
        if os.path.exists("init"):
            return

        if not os.path.exists(self._config_path):
            raise FileNotFoundError(
                f"Configuration file {self._config_path!r} not found."
            )

        with open(self._config_path, "r", encoding="utf-8") as f:
            toml_doc = parse(f.read())

        toml_doc["server"]["secret_key"] = secrets.token_hex(32)
        toml_doc["security"]["pepper"] = secrets.token_hex(32)

        with open(self._config_path, "w", encoding="utf-8") as f:
            f.write(dumps(toml_doc))

    # -- loading ----------------------------------------------------------

    def _load(self):
        with open(self._config_path, "r", encoding="utf-8") as f:
            new_data = parse(f.read())

        with self._lock:
            self._data = new_data

        if self._initialized:
            logger.info(f"Configuration reloaded from {self._config_path}")

    # -- watchdog ---------------------------------------------------------

    def _start_watching(self):
        watch_dir = str(self._config_path.parent)
        observer = Observer()
        observer.schedule(
            _ConfigEventHandler(self, self._config_path),
            watch_dir,
            recursive=False,
        )
        observer.daemon = True
        observer.start()
        self._observer = observer

    def reload(self):
        """Force an immediate reload (also called by the watchdog handler)."""
        self._load()

    def stop(self):
        """Stop the watchdog observer (e.g. during graceful shutdown)."""
        if self._observer:
            self._observer.stop()
            self._observer.join()

    # -- dict-like access (thread-safe reads) -----------------------------

    def __getitem__(self, key: str) -> Any:
        with self._lock:
            return self._data[key]

    @overload
    def get(self, key: str, /) -> Any | None: ...

    @overload
    def get[_T](self, key: str, default: _T, /) -> Any | _T: ...

    def get(self, key: str, default: Any = None, /) -> Any:
        with self._lock:
            return self._data.get(key, default)

    def __contains__(self, key: str):
        with self._lock:
            return key in self._data

    def __repr__(self):
        with self._lock:
            return (
                f"GlobalConfig(path={self._config_path!r}, "
                f"keys={list(self._data.keys())})"
            )


# Module-level singleton – imported everywhere as `global_config`.
global_config: Final = GlobalConfig()

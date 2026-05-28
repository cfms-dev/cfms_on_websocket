"""include/conf_loader.py

This module loads the global configuration from a TOML file and exposes it
as a thread-safe, dict-like singleton that automatically reloads when the
config file changes on disk.

The watchdog observer monitors the *directory* containing the config file
rather than the file itself, so that atomic replacements (write-to-temp +
rename, or symlink updates) are detected reliably.
"""

import pathlib
import threading
import tomllib

from loguru import logger
from watchdog.events import FileSystemEventHandler
from watchdog.observers import Observer
from watchdog.observers.api import BaseObserver

__all__ = ["global_config"]


class _ConfigEventHandler(FileSystemEventHandler):
    """Watchdog handler that triggers a config reload on any file event in the
    watched directory.  Debounces rapid-fire events to avoid parsing the file
    while it is still being written."""

    def __init__(self, config: "GlobalConfig"):
        self._config = config
        self._debounce_timer: threading.Timer | None = None
        self._debounce_sec = 0.5

    def _schedule_reload(self):
        if self._debounce_timer:
            self._debounce_timer.cancel()
        self._debounce_timer = threading.Timer(self._debounce_sec, self._config.reload)
        self._debounce_timer.daemon = True
        self._debounce_timer.start()

    def on_modified(self, event):
        if event.is_directory:
            return
        self._schedule_reload()

    def on_created(self, event):
        if event.is_directory:
            return
        self._schedule_reload()

    def on_moved(self, event):
        if event.is_directory:
            return
        self._schedule_reload()


class GlobalConfig:
    """Thread-safe global configuration backed by a TOML file.

    Watches the config file's *directory* so that atomic write patterns
    (write-to-temp + rename, symlink swaps) are picked up.  Supports
    dict-like read access for backward compatibility.
    """

    def __init__(self, config_path: str = "config.toml"):
        self._config_path = pathlib.Path(config_path).resolve()
        self._data: dict = {}
        self._lock = threading.Lock()
        self._observer: BaseObserver | None = None

        self._load()
        self._start_watching()

    # -- loading ----------------------------------------------------------

    def _load(self):
        try:
            with open(self._config_path, "rb") as f:
                new_data = tomllib.load(f)
        except Exception:
            logger.exception(f"Failed to read config from {self._config_path}")
            return

        with self._lock:
            self._data = new_data
        logger.info(f"Configuration reloaded from {self._config_path}")

    # -- watchdog ---------------------------------------------------------

    def _start_watching(self):
        watch_dir = str(self._config_path.parent)
        observer = Observer()
        observer.schedule(
            _ConfigEventHandler(self),
            watch_dir,
            recursive=False,
        )
        observer.daemon = True
        observer.start()
        self._observer = observer
        logger.debug(f"Watching directory for config changes: {watch_dir}")

    def reload(self):
        """Force an immediate reload (also called by the watchdog handler)."""
        self._load()

    def stop(self):
        """Stop the watchdog observer (e.g. during graceful shutdown)."""
        if self._observer:
            self._observer.stop()
            self._observer.join()

    # -- dict-like access (thread-safe reads) -----------------------------

    def __getitem__(self, key: str):
        with self._lock:
            return self._data[key]

    def get(self, key: str, default=None):
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
global_config = GlobalConfig()

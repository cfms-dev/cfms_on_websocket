from __future__ import annotations

__all__ = [
    "pm",
    "collect_extension_flags",
    "load_builtin_extension",
    "load_extensions_from_directory",
]

import importlib.util
import os
import sys
from pathlib import Path
from typing import TYPE_CHECKING

import pluggy
import websockets.sync.server
from loguru import logger as log

if TYPE_CHECKING:
    from include.transport.connection import ConnectionHandler
    from include.transport.request_handler import RequestHandler, Result

hookspec = pluggy.HookspecMarker("cfms")
hookimpl = pluggy.HookimplMarker("cfms")

logger = log.bind(name="ext_manager")


# ext = extension
class ServerHookSpecs:
    """Hook specifications for server extensions."""

    @hookspec
    def ext_register_handlers(self) -> dict[str, type[RequestHandler]]:
        """Register handlers for specific actions.

        Should return a dictionary mapping action names to their
        corresponding RequestHandler classes.
        """
        ...

    @hookspec
    def ext_unregister_handlers(self) -> set[str]:
        """Unregister handlers for specific actions.

        Should return a set of action names whose handlers should
        be unregistered.
        """
        ...

    @hookspec
    def ext_register_whitelisted_actions(self) -> set[str]:
        """
        Register actions that should be whitelisted (allowed even
        during lockdown).

        Should return a set of action names.
        """
        ...

    @hookspec
    def ext_register_extension_flags(self) -> set[str]:
        """
        Register extension capability flags advertised by server_info.

        Should return a set of string flags that are currently enabled.
        """
        ...

    @hookspec
    def ext_on_connect(self, websocket: websockets.sync.server.ServerConnection):
        """
        Triggered when a new client connects, providing the websocket
        connection object.
        """

    @hookspec
    def ext_post_disconnect(self):
        """
        Triggered after a client disconnects, regardless of
        the reason.
        """

    @hookspec(firstresult=True)
    def ext_pre_request(
        self, request_handler: "RequestHandler", connection_handler: "ConnectionHandler"
    ) -> bool | None:
        """
        Triggered before processing a request.

        If any extension returns False, the request will be rejected
        immediately.
        """

    @hookspec
    def ext_post_request(
        self,
        action: str,
        handler: "ConnectionHandler",
        callback: Result | None,
        time_cost: float,
    ) -> None: ...

    @hookspec
    def ext_on_file_uploaded(self, id: str, path: str, sha256: str):
        """
        Triggered when a file is uploaded to the server, providing the
        file's id, path, and sha256 hash.

        This can be used to implement features like file deduplication,
        virus scanning, or triggering post-upload processing.
        """

    @hookspec
    def ext_on_empty_file_uploaded(self, id: str, path: str):
        """
        Triggered when an empty file is uploaded to the server,
        providing the filename. This can be used to clean up
        placeholder files that were created but never filled.
        """


def _load_extension(
    extension_dir: str | Path,
    ext_name: str,
    *,
    quiet: bool = False,
) -> bool:
    extension_path = Path(extension_dir) / ext_name
    entrypoint = extension_path / "_extension.py"

    if not entrypoint.is_file():
        return False

    try:
        spec = importlib.util.spec_from_file_location(ext_name, entrypoint)
        if spec is None or spec.loader is None:
            logger.error(f"Failed to load spec for extension: {ext_name}")
            return False

        spec.submodule_search_locations = [str(extension_path)]

        module = importlib.util.module_from_spec(spec)
        sys.modules[ext_name] = module

        try:
            spec.loader.exec_module(module)
        except Exception:
            del sys.modules[ext_name]
            raise

        pm.register(module, name=ext_name)

        if not quiet:
            logger.info(f"Loaded extension: {ext_name}")
        return True

    except Exception as e:
        logger.exception(f"Failed to load extension '{ext_name}': {e}")
        return False


def load_builtin_extension(extension_dir: str | Path):
    if pm.has_plugin("builtin"):
        return

    _load_extension(extension_dir, "builtin", quiet=True)


def load_extensions_from_directory(extension_dir: str | Path):

    if not os.path.isdir(extension_dir):
        logger.warning(
            f"Extension directory '{extension_dir}' does not exist or is not a directory. Skipping."
        )
        return

    loaded_extensions = set()

    for filename in sorted(os.listdir(extension_dir)):
        if filename.startswith(("_", ".")):
            continue

        ext_path = os.path.join(extension_dir, filename)
        if not os.path.isdir(ext_path):
            continue

        ext_name = filename
        if ext_name in loaded_extensions:
            logger.warning(
                f"Skipping: Found a duplicate {filename} for extension '{ext_name}'"
            )
            continue

        if pm.has_plugin(ext_name):
            continue

        if not _load_extension(extension_dir, ext_name):
            continue

        loaded_extensions.add(ext_name)


def collect_extension_flags() -> list[str]:
    flags: set[str] = set()

    for registered_flags in pm.hook.ext_register_extension_flags():
        if registered_flags is None:
            continue

        for flag in registered_flags:
            if not isinstance(flag, str):
                logger.warning(f"Ignoring non-string extension flag: {flag!r}")
                continue

            flags.add(flag)

    return sorted(flags)


pm = pluggy.PluginManager("cfms")
pm.add_hookspecs(ServerHookSpecs)

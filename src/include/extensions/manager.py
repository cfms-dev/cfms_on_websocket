__all__ = [
    "DiscoveredExtension",
    "ExtensionDiscoveryError",
    "ExtensionManifest",
    "ExtensionManifestError",
    "collect_extension_flags",
    "discover_extensions",
    "load_builtin_extension",
    "load_extensions_from_directory",
    "parse_extension_manifest",
    "pm",
]

import importlib.util
import os
import re
import sys
import tomllib
from dataclasses import dataclass
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

MANIFEST_FILENAME = "extension.toml"
ENTRYPOINT_FILENAME = "_extension.py"
SUPPORTED_MANIFEST_VERSION = 1
IDENTIFIER_PATTERN = re.compile(r"^[a-z][a-z0-9_]*$")
REQUIRED_MANIFEST_FIELDS = {
    "manifest_version",
    "identifier",
    "name",
    "version",
    "authors",
    "license",
}
OPTIONAL_MANIFEST_FIELDS = {"description", "homepage"}


class ExtensionManifestError(ValueError):
    """Raised when an extension manifest is missing or invalid."""


class ExtensionDiscoveryError(RuntimeError):
    """Raised when the extension catalog cannot be discovered safely."""


@dataclass(frozen=True, slots=True)
class ExtensionManifest:
    manifest_version: int
    identifier: str
    name: str
    version: str
    authors: tuple[str, ...]
    license: str
    description: str | None = None
    homepage: str | None = None


@dataclass(frozen=True, slots=True)
class DiscoveredExtension:
    manifest: ExtensionManifest
    directory: Path
    entrypoint: Path


def _required_string(data: dict, field: str, manifest_path: Path) -> str:
    value = data[field]
    if not isinstance(value, str) or not value.strip():
        raise ExtensionManifestError(
            f"{manifest_path}: {field!r} must be a non-empty string"
        )
    return value.strip()


def _optional_string(data: dict, field: str, manifest_path: Path) -> str | None:
    if field not in data:
        return None
    value = data[field]
    if not isinstance(value, str) or not value.strip():
        raise ExtensionManifestError(
            f"{manifest_path}: {field!r} must be a non-empty string when provided"
        )
    return value.strip()


def parse_extension_manifest(manifest_path: str | Path) -> ExtensionManifest:
    """Parse and validate a versioned extension manifest."""
    path = Path(manifest_path)
    try:
        with path.open("rb") as manifest_file:
            data = tomllib.load(manifest_file)
    except (OSError, tomllib.TOMLDecodeError) as exc:
        raise ExtensionManifestError(f"Failed to read {path}: {exc}") from exc

    fields = set(data)
    missing = sorted(REQUIRED_MANIFEST_FIELDS - fields)
    if missing:
        raise ExtensionManifestError(
            f"{path}: missing required fields: {', '.join(missing)}"
        )
    unknown = sorted(fields - REQUIRED_MANIFEST_FIELDS - OPTIONAL_MANIFEST_FIELDS)
    if unknown:
        raise ExtensionManifestError(f"{path}: unknown fields: {', '.join(unknown)}")

    manifest_version = data["manifest_version"]
    if isinstance(manifest_version, bool) or not isinstance(manifest_version, int):
        raise ExtensionManifestError(f"{path}: 'manifest_version' must be an integer")
    if manifest_version != SUPPORTED_MANIFEST_VERSION:
        raise ExtensionManifestError(
            f"{path}: unsupported manifest_version {manifest_version}; "
            f"expected {SUPPORTED_MANIFEST_VERSION}"
        )

    identifier = _required_string(data, "identifier", path)
    if IDENTIFIER_PATTERN.fullmatch(identifier) is None:
        raise ExtensionManifestError(
            f"{path}: invalid extension identifier {identifier!r}"
        )

    authors = data["authors"]
    if not isinstance(authors, list) or not authors:
        raise ExtensionManifestError(
            f"{path}: 'authors' must be a non-empty array of strings"
        )
    if any(not isinstance(author, str) or not author.strip() for author in authors):
        raise ExtensionManifestError(
            f"{path}: 'authors' must be a non-empty array of strings"
        )

    return ExtensionManifest(
        manifest_version=manifest_version,
        identifier=identifier,
        name=_required_string(data, "name", path),
        version=_required_string(data, "version", path),
        authors=tuple(author.strip() for author in authors),
        license=_required_string(data, "license", path),
        description=_optional_string(data, "description", path),
        homepage=_optional_string(data, "homepage", path),
    )


def discover_extensions(extension_dir: str | Path) -> dict[str, DiscoveredExtension]:
    """Discover and validate all extension candidates in a directory."""
    root = Path(extension_dir)
    if not root.is_dir():
        raise ExtensionDiscoveryError(
            f"Extension directory {str(root)!r} does not exist or is not a directory"
        )

    discovered: dict[str, DiscoveredExtension] = {}
    for extension_path in sorted(root.iterdir(), key=lambda path: path.name):
        if extension_path.name.startswith(("_", ".")) or not extension_path.is_dir():
            continue

        manifest_path = extension_path / MANIFEST_FILENAME
        entrypoint = extension_path / ENTRYPOINT_FILENAME
        has_manifest = manifest_path.is_file()
        has_entrypoint = entrypoint.is_file()
        if not has_manifest and not has_entrypoint:
            continue
        if not has_manifest:
            raise ExtensionDiscoveryError(
                f"Extension candidate {extension_path} is missing {MANIFEST_FILENAME}"
            )
        if not has_entrypoint:
            raise ExtensionDiscoveryError(
                f"Extension candidate {extension_path} is missing {ENTRYPOINT_FILENAME}"
            )

        try:
            manifest = parse_extension_manifest(manifest_path)
        except ExtensionManifestError as exc:
            raise ExtensionDiscoveryError(str(exc)) from exc

        previous = discovered.get(manifest.identifier)
        if previous is not None:
            raise ExtensionDiscoveryError(
                f"Duplicate extension identifier {manifest.identifier!r} in "
                f"{previous.directory} and {extension_path}"
            )
        discovered[manifest.identifier] = DiscoveredExtension(
            manifest=manifest,
            directory=extension_path,
            entrypoint=entrypoint,
        )

    return discovered


# ext = extension
class ServerHookSpecs:
    """Hook specifications for server extensions."""

    @hookspec
    def ext_register_handlers(self) -> dict[str, type["RequestHandler"]]:
        """Register handlers for specific actions.

        Should return a dictionary mapping action names to their
        corresponding RequestHandler classes.
        """

    @hookspec
    def ext_unregister_handlers(self) -> set[str]:
        """Unregister handlers for specific actions.

        Should return a set of action names whose handlers should
        be unregistered.
        """

    @hookspec
    def ext_register_whitelisted_actions(self) -> set[str]:
        """
        Register actions that should be whitelisted (allowed even
        during lockdown).

        Should return a set of action names.
        """

    @hookspec
    def ext_register_extension_flags(self) -> set[str]:
        """
        Register extension capability flags advertised by server_info.

        Should return a set of string flags that are currently enabled.
        """

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
        self,
        request_handler: "RequestHandler",
        connection_handler: "ConnectionHandler",
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
        callback: "Result | None",
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

    except Exception:
        logger.exception(f"Failed to load extension '{ext_name}'")
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
        for flag in registered_flags:
            if not isinstance(flag, str):
                logger.warning(f"Ignoring non-string extension flag: {flag!r}")
                continue

            flags.add(flag)

    return sorted(flags)


pm = pluggy.PluginManager("cfms")
pm.add_hookspecs(ServerHookSpecs)

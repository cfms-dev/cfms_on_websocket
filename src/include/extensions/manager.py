__all__ = [
    "DiscoveredExtension",
    "ExtensionCompatibility",
    "ExtensionDependencies",
    "ExtensionDiscoveryError",
    "ExtensionLoadError",
    "ExtensionManifest",
    "ExtensionManifestError",
    "ExtensionMetadata",
    "collect_extension_flags",
    "discover_extensions",
    "get_loaded_extension_metadata",
    "load_extensions_from_directory",
    "parse_extension_manifest",
    "pm",
    "validate_extension_config",
]

import importlib.util
import sys
import tomllib
from abc import ABC, abstractmethod
from collections.abc import Mapping
from dataclasses import dataclass
from pathlib import Path
from typing import TYPE_CHECKING, Annotated, Any, Literal

import pluggy
import websockets.sync.server
from loguru import logger as log
from packaging.version import InvalidVersion
from packaging.version import Version as PackageVersion
from pydantic import (
    BaseModel,
    ConfigDict,
    Field,
    ValidationError,
    field_validator,
    model_validator,
)

from include.config.constants import CORE_VERSION
from include.config.version import Version
from include.extensions.identifiers import ExtensionIdentifier
from include.types import TrimmedNonEmptyString

if TYPE_CHECKING:
    from sqlalchemy.orm import Session as OrmSession

    from include.transport.connection import ConnectionHandler
    from include.transport.request_handler import RequestHandler, Result

hookspec = pluggy.HookspecMarker("cfms")
hookimpl = pluggy.HookimplMarker("cfms")

logger = log.bind(name="ext_manager")

MANIFEST_FILENAME = "manifest.toml"
ENTRYPOINT_FILENAME = "_extension.py"


class ExtensionManifestError(ValueError):
    """Raised when an extension manifest is missing or invalid."""


class ExtensionDiscoveryError(RuntimeError):
    """Raised when the extension catalog cannot be discovered safely."""


class ExtensionLoadError(RuntimeError):
    """Raised when a configured extension cannot be loaded."""


class ExtensionMetadata(BaseModel):
    model_config = ConfigDict(
        extra="forbid",
        frozen=True,
        strict=True,
    )

    identifier: ExtensionIdentifier
    name: TrimmedNonEmptyString
    version: TrimmedNonEmptyString
    authors: Annotated[
        tuple[TrimmedNonEmptyString, ...],
        Field(min_length=1, strict=False),
    ]
    license: TrimmedNonEmptyString
    description: TrimmedNonEmptyString | None = None
    homepage: TrimmedNonEmptyString | None = None


_loaded_extension_metadata: dict[str, ExtensionMetadata] = {}


class ExtensionCompatibility(BaseModel):
    model_config = ConfigDict(
        arbitrary_types_allowed=True,
        extra="forbid",
        frozen=True,
        strict=True,
    )

    minimum_server_version: Version | None = None

    @field_validator("minimum_server_version", mode="before")
    @classmethod
    def parse_minimum_server_version(cls, value):
        if isinstance(value, str):
            return Version(value)
        return value


class ExtensionDependencies(BaseModel):
    model_config = ConfigDict(
        extra="forbid",
        frozen=True,
        strict=True,
    )

    extensions: dict[ExtensionIdentifier, TrimmedNonEmptyString] = Field(
        default_factory=dict
    )

    @field_validator("extensions")
    @classmethod
    def validate_minimum_versions(cls, value):
        for identifier, minimum_version in value.items():
            try:
                PackageVersion(minimum_version)
            except InvalidVersion as exc:
                raise ValueError(
                    f"Invalid minimum version for extension {identifier!r}: "
                    f"{minimum_version!r}"
                ) from exc
        return value


class ExtensionManifest(BaseModel):
    model_config = ConfigDict(
        extra="forbid",
        frozen=True,
        strict=True,
    )

    manifest_version: Literal[2, 3]
    extension: ExtensionMetadata
    compatibility: ExtensionCompatibility = Field(
        default_factory=ExtensionCompatibility
    )
    dependencies: ExtensionDependencies = Field(default_factory=ExtensionDependencies)

    @model_validator(mode="after")
    def validate_manifest_version_contract(self):
        if self.manifest_version == 2 and "dependencies" in self.model_fields_set:
            raise ValueError("manifest version 2 does not support dependencies")
        if self.manifest_version == 3:
            try:
                PackageVersion(self.extension.version)
            except InvalidVersion as exc:
                raise ValueError(
                    "manifest version 3 requires a valid PEP 440 extension version"
                ) from exc
        return self


@dataclass(frozen=True, slots=True)
class DiscoveredExtension:
    manifest: ExtensionManifest
    directory: Path
    entrypoint: Path


def parse_extension_manifest(
    manifest_path: str | Path,
) -> ExtensionManifest:
    path = Path(manifest_path)

    try:
        with path.open("rb") as manifest_file:
            data = tomllib.load(manifest_file)

        return ExtensionManifest.model_validate(data)

    except (OSError, tomllib.TOMLDecodeError) as exc:
        raise ExtensionManifestError(f"Failed to read {path}: {exc}") from exc

    except ValidationError as exc:
        details = "; ".join(
            f"{'.'.join(str(part) for part in error['loc']) or '<manifest>'}: "
            f"{error['msg']}"
            for error in exc.errors(
                include_url=False,
                include_context=False,
                include_input=False,
            )
        )
        raise ExtensionManifestError(
            f"{path}: invalid extension manifest: {details}"
        ) from exc


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

        metadata = manifest.extension
        previous = discovered.get(metadata.identifier)
        if previous is not None:
            raise ExtensionDiscoveryError(
                f"Duplicate extension identifier {metadata.identifier!r} in "
                f"{previous.directory} and {extension_path}"
            )
        discovered[metadata.identifier] = DiscoveredExtension(
            manifest=manifest,
            directory=extension_path,
            entrypoint=entrypoint,
        )

    return discovered


# ext = extension
class ServerHookSpecs(ABC):
    """Hook specifications for server extensions."""

    @hookspec
    @abstractmethod
    def ext_validate_config(self, config: Mapping[str, Any]) -> None:
        """Validate extension-owned configuration values.

        Implementations should raise :class:`ConfigValidationError` when the
        supplied configuration is invalid.
        """

    @hookspec
    @abstractmethod
    def ext_register_handlers(self) -> dict[str, type["RequestHandler"]]:
        """Register handlers for specific actions.

        Should return a dictionary mapping action names to their corresponding
        :class:`RequestHandler` classes. Each handler must define a
        :class:`RequestDataModel` subclass as ``request_model``.
        """

    @hookspec
    @abstractmethod
    def ext_unregister_handlers(self) -> set[str]:
        """Unregister handlers for specific actions.

        Should return a set of action names whose handlers should be unregistered.
        """

    @hookspec
    @abstractmethod
    def ext_register_whitelisted_actions(self) -> set[str]:
        """
        Register actions that should be whitelisted (allowed even during lockdown).

        Should return a set of action names. Note that this hook does not encompass
        the functionality of `ext_register_handlers`.
        """

    @hookspec
    @abstractmethod
    def ext_register_extension_flags(self) -> set[str]:
        """
        Register extension capability flags advertised by server_info.

        Should return a set of string flags that are currently enabled.
        """

    @hookspec
    @abstractmethod
    def ext_on_startup(self, server: websockets.sync.server.Server) -> None:
        """Start extension-owned background services.

        This hook runs after the database, providers, and request handlers are
        ready, immediately before the server enters its serving loop. Hook
        implementations may omit ``server`` when they don't need direct access
        to the WebSocket server.
        """

    @hookspec
    @abstractmethod
    def ext_on_shutdown(self) -> None:
        """Stop extension-owned background services.

        Implementations must be idempotent because this hook also runs when a
        startup hook raises after another extension has already started.
        """

    @hookspec
    @abstractmethod
    def ext_on_connect(
        self, websocket: websockets.sync.server.ServerConnection
    ) -> None:
        """
        Triggered when a new client connects, providing the websocket
        connection object.
        """

    @hookspec
    @abstractmethod
    def ext_post_disconnect(self) -> None:
        """
        Triggered after a client disconnects, regardless of
        the reason.
        """

    @hookspec(firstresult=True)
    @abstractmethod
    def ext_before_request(
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
    @abstractmethod
    def ext_post_request(
        self,
        action: str,
        handler: "ConnectionHandler",
        callback: "Result | None",
        time_cost: float,
    ) -> None:
        """Triggered after a request has been processed and its result audited."""

    @hookspec
    @abstractmethod
    def ext_before_file_upload_finalize(
        self,
        session: "OrmSession",
        id: str,
        path: str,
        sha256: str,
    ) -> None:
        """Run inside a non-empty upload's completion transaction.

        Extensions may persist work through ``session`` so that it commits or
        rolls back atomically with the completed upload. Implementations must
        not commit or close the supplied session.
        """

    @hookspec
    @abstractmethod
    def ext_on_file_upload_completed(self, id: str, path: str, sha256: str) -> None:
        """Run after a non-empty upload's success response has been sent.

        Implementations must handle their own failures because the upload is
        already complete and acknowledged to the client.
        """


def _rollback_extension(ext_name: str) -> None:
    pm.unregister(name=ext_name)
    _loaded_extension_metadata.pop(ext_name, None)
    sys.modules.pop(ext_name, None)


def _rollback_extensions(extensions: list[DiscoveredExtension]) -> None:
    for extension in reversed(extensions):
        _rollback_extension(extension.manifest.extension.identifier)


def _load_extension(extension: DiscoveredExtension) -> None:
    ext_name = extension.manifest.extension.identifier
    registered = False
    try:
        spec = importlib.util.spec_from_file_location(ext_name, extension.entrypoint)
        if spec is None or spec.loader is None:
            raise ExtensionLoadError(f"Failed to load spec for extension: {ext_name}")

        spec.submodule_search_locations = [str(extension.directory)]

        module = importlib.util.module_from_spec(spec)
        sys.modules[ext_name] = module
        spec.loader.exec_module(module)
        pm.register(module, name=ext_name)
        _loaded_extension_metadata[ext_name] = extension.manifest.extension
        registered = True
    except ExtensionLoadError:
        raise
    except Exception as exc:
        raise ExtensionLoadError(f"Failed to load extension {ext_name!r}") from exc
    finally:
        if not registered:
            _rollback_extension(ext_name)


def _find_dependency_cycle(
    dependencies: dict[str, tuple[str, ...]],
    selected: tuple[str, ...],
) -> tuple[str, ...]:
    visiting: set[str] = set()
    visited: set[str] = set()
    path: list[str] = []

    def visit(identifier: str) -> tuple[str, ...] | None:
        if identifier in visiting:
            start = path.index(identifier)
            return (*path[start:], identifier)
        if identifier in visited:
            return None

        visiting.add(identifier)
        path.append(identifier)
        for dependency in dependencies[identifier]:
            cycle = visit(dependency)
            if cycle is not None:
                return cycle
        path.pop()
        visiting.remove(identifier)
        visited.add(identifier)
        return None

    for identifier in selected:
        cycle = visit(identifier)
        if cycle is not None:
            return cycle
    return ()


def _resolve_extension_load_order(
    discovered: dict[str, DiscoveredExtension],
    selected: tuple[str, ...],
) -> tuple[DiscoveredExtension, ...]:
    selected_set = set(selected)
    order_index = {identifier: index for index, identifier in enumerate(selected)}
    dependencies: dict[str, tuple[str, ...]] = {}
    dependents: dict[str, list[str]] = {identifier: [] for identifier in selected}
    indegree: dict[str, int] = {}

    for identifier in selected:
        extension = discovered[identifier]
        required = tuple(extension.manifest.dependencies.extensions)
        if identifier == "builtin" and required:
            raise ExtensionLoadError(
                "The built-in extension cannot declare extension dependencies"
            )
        if identifier in required:
            raise ExtensionLoadError(
                f"Extension {identifier!r} cannot depend on itself"
            )
        for (
            dependency,
            minimum_version,
        ) in extension.manifest.dependencies.extensions.items():
            installed = discovered.get(dependency)
            if installed is None:
                raise ExtensionLoadError(
                    f"Extension {identifier!r} requires extension {dependency!r}, "
                    "but it is not installed"
                )
            if dependency not in selected_set:
                raise ExtensionLoadError(
                    f"Extension {identifier!r} requires extension {dependency!r}, "
                    "but it is not enabled"
                )
            try:
                installed_version = PackageVersion(installed.manifest.extension.version)
            except InvalidVersion as exc:
                raise ExtensionLoadError(
                    f"Extension {dependency!r} has an invalid version "
                    f"{installed.manifest.extension.version!r}"
                ) from exc
            required_version = PackageVersion(minimum_version)
            if installed_version < required_version:
                raise ExtensionLoadError(
                    f"Extension {identifier!r} requires extension {dependency!r} "
                    f"version {minimum_version} or newer; installed version is "
                    f"{installed.manifest.extension.version}"
                )
            dependents[dependency].append(identifier)
        dependencies[identifier] = required
        indegree[identifier] = len(required)

    ready = [identifier for identifier in selected if indegree[identifier] == 0]
    resolved = []
    while ready:
        ready.sort(key=order_index.__getitem__)
        identifier = ready.pop(0)
        resolved.append(identifier)
        for dependent in dependents[identifier]:
            indegree[dependent] -= 1
            if indegree[dependent] == 0:
                ready.append(dependent)

    if len(resolved) != len(selected):
        cycle = _find_dependency_cycle(dependencies, selected)
        raise ExtensionLoadError(
            "Extension dependency cycle detected: " + " -> ".join(cycle)
        )

    return tuple(discovered[identifier] for identifier in resolved)


def validate_extension_config(config: Any) -> None:
    """Validate configuration through all registered extension hooks."""
    pm.hook.ext_validate_config(config=config)


def load_extensions_from_directory(
    extension_dir: str | Path,
    enabled_identifiers: tuple[str, ...] | list[str],
    *,
    config: Any,
) -> None:
    """Load the built-in extension and configured extensions in order."""
    discovered = discover_extensions(extension_dir)
    builtin_ext = discovered.get("builtin")
    if builtin_ext is None:
        raise ExtensionDiscoveryError(
            f"Required built-in extension was not found in {extension_dir}"
        )

    enabled = tuple(enabled_identifiers)
    if len(enabled) != len(set(enabled)):
        raise ExtensionDiscoveryError("Enabled extension identifiers must be unique")
    if "builtin" in enabled:
        raise ExtensionDiscoveryError(
            "The built-in extension is always loaded and must not be configured"
        )
    missing = [identifier for identifier in enabled if identifier not in discovered]
    if missing:
        raise ExtensionDiscoveryError(
            "Configured extensions were not found: " + ", ".join(missing)
        )

    selected_identifiers = ("builtin", *enabled)
    ordered_extensions = _resolve_extension_load_order(discovered, selected_identifiers)

    for extension in ordered_extensions:
        minimum_version = extension.manifest.compatibility.minimum_server_version
        if minimum_version is not None and CORE_VERSION < minimum_version:
            identifier = extension.manifest.extension.identifier
            raise ExtensionLoadError(
                f"Extension {identifier!r} requires server version "
                f"{minimum_version} or newer; current server version is {CORE_VERSION}"
            )

    extensions_to_load = [
        extension
        for extension in ordered_extensions
        if not pm.has_plugin(extension.manifest.extension.identifier)
    ]

    loaded_extensions: list[DiscoveredExtension] = []
    try:
        for extension in extensions_to_load:
            _load_extension(extension)
            loaded_extensions.append(extension)
        validate_extension_config(config)
    except ExtensionLoadError:
        _rollback_extensions(loaded_extensions)
        raise
    except Exception as exc:
        _rollback_extensions(loaded_extensions)
        raise ExtensionLoadError(
            f"Failed to validate loaded extension configuration: {exc}"
        ) from exc

    for extension in loaded_extensions:
        metadata = extension.manifest.extension
        if metadata.identifier != "builtin":
            logger.info(
                f"Loaded extension: {metadata.name} ({metadata.version}) "
                f"({metadata.identifier})"
            )


def collect_extension_flags() -> list[str]:
    flags: set[str] = set()

    for registered_flags in pm.hook.ext_register_extension_flags():
        for flag in registered_flags:
            if not isinstance(flag, str):
                logger.warning(f"Ignoring non-string extension flag: {flag!r}")
                continue

            flags.add(flag)

    return sorted(flags)


def get_loaded_extension_metadata() -> tuple[ExtensionMetadata, ...]:
    return tuple(_loaded_extension_metadata.values())


pm = pluggy.PluginManager("cfms")
pm.add_hookspecs(ServerHookSpecs)

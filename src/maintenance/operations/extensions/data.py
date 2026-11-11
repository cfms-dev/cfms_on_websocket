from contextlib import nullcontext

from pydantic import ValidationError
from sqlalchemy import delete, func, select

from include.extensions import manager as extension_manager
from include.extensions.identifiers import validate_extension_identifier
from include.runtime_lock import RuntimeLockError, server_runtime_lock
from maintenance.operations.exceptions import MaintenanceOperationError
from maintenance.operations.extensions.catalog import (
    _discover,
    _extension_root,
    _read_config,
)
from maintenance.operations.extensions.models import ExtensionDataPurgeResult
from maintenance.runtime import enter_server_root, load_database_models
lazy from include.database.models.operations import (
    AuditEntry,
    OptionEntry,
    SystemStateEntry,
)
lazy from include.database.session import Session


def _purge_extension_data(
    identifier: str,
    *,
    options_only: bool,
    write: bool,
    allow_enabled_preview: bool = False,
) -> ExtensionDataPurgeResult:
    if identifier in ("core", "builtin"):
        raise MaintenanceOperationError(
            f"Data owned by {identifier!r} cannot be purged as extension data"
        )
    try:
        validate_extension_identifier(identifier)
    except ValidationError as exc:
        raise MaintenanceOperationError("Invalid extension identifier") from exc
    workdir = enter_server_root()
    _, _, _, enabled = _read_config(workdir)
    if identifier in enabled and (write or not allow_enabled_preview):
        raise MaintenanceOperationError(
            f"Disable extension {identifier!r} before purging its data"
        )
    if not options_only:
        _, root = _extension_root(mutating=True)
        if identifier not in _discover(root):
            raise MaintenanceOperationError(
                f"Extension {identifier!r} is not installed"
            )

    load_database_models()
    context = (
        extension_manager.maintenance_extension_context(identifier)
        if write and not options_only
        else nullcontext()
    )
    try:
        with context, Session.begin() as session:
            option_entries = session.execute(
                select(func.count())
                .select_from(OptionEntry)
                .where(OptionEntry.owner == identifier)
            ).scalar_one()
            state_entries = session.execute(
                select(func.count())
                .select_from(SystemStateEntry)
                .where(SystemStateEntry.owner == identifier)
            ).scalar_one()
            if write:
                if not options_only:
                    extension_manager.purge_extension_data(identifier, session)
                session.execute(
                    delete(OptionEntry).where(OptionEntry.owner == identifier)
                )
                session.execute(
                    delete(SystemStateEntry).where(SystemStateEntry.owner == identifier)
                )
                session.add(
                    AuditEntry(
                        action="purge_extension_data",
                        result=0,
                        target=identifier,
                        data={
                            "owner": identifier,
                            "options_only": options_only,
                            "option_entries": option_entries,
                            "state_entries": state_entries,
                        },
                    )
                )
    except Exception as exc:
        raise MaintenanceOperationError(
            f"Unable to purge data for extension {identifier!r}; database changes "
            "were rolled back and extension code was preserved"
        ) from exc
    return ExtensionDataPurgeResult(
        identifier=identifier,
        options_only=options_only,
        option_entries=option_entries,
        state_entries=state_entries,
        applied=write,
    )


def purge_extension_data(
    identifier: str, *, options_only: bool = False, write: bool = False
) -> ExtensionDataPurgeResult:
    """Purge one disabled owner's data while excluding the running server."""
    workdir = enter_server_root()
    try:
        with server_runtime_lock(workdir):
            return _purge_extension_data(
                identifier, options_only=options_only, write=write
            )
    except RuntimeLockError as exc:
        raise MaintenanceOperationError(str(exc)) from exc

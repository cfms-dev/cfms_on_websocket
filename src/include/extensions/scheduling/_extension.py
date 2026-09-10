"""Pluggy entry point for the optional scheduling management API."""

from include.extensions.manager import hookimpl

from .handlers import HANDLERS


@hookimpl
def ext_register_handlers():
    """Expose authenticated schedule-management actions to the WebSocket router."""

    return HANDLERS


@hookimpl
def ext_register_extension_flags():
    """Advertise availability of the scheduling management protocol."""

    return {"scheduling"}

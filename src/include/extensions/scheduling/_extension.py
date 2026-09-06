from include.extensions.manager import hookimpl

from .handlers import HANDLERS


@hookimpl
def ext_register_handlers():
    return HANDLERS


@hookimpl
def ext_register_extension_flags():
    return {"scheduling"}

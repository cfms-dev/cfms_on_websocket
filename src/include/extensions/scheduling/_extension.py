from include.extensions.manager import (
    collect_scheduled_tasks,
    hookimpl,
)
from include.providers.manager import ProviderManager


@hookimpl
def ext_register_handlers():
    return {}


@hookimpl
def ext_register_extension_flags():
    return {"scheduling"}


@hookimpl
def ext_register_scheduled_tasks():
    return ()


@hookimpl
def ext_on_startup() -> None:
    ProviderManager().scheduling.start(collect_scheduled_tasks())


@hookimpl
def ext_on_shutdown() -> None:
    ProviderManager().scheduling.shutdown()

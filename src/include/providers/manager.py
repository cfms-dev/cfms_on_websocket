__all__ = ["ProviderManager"]

from typing import cast

from include.providers.base import (
    CachingProvider,
    EventBusProvider,
    Provider,
    StorageProvider,
)


class ProviderManager:
    """
    Manager for providers.

    This class provides a centralized way to access different providers.
    """

    _initialized = False

    def __new__(cls):
        if not hasattr(cls, "_instance"):
            cls._instance = super().__new__(cls)
        return cls._instance

    def __init__(self):
        if self._initialized:
            return

        self._providers: dict[str, Provider] = {}
        self._initialized = True

    def register(self, provider: Provider, /) -> None:
        self._providers[provider.identifier] = provider

    def get[T: Provider](self, cls: type[T], /) -> T:
        if cls.identifier not in self._providers:
            raise ValueError(f"Provider '{cls.identifier}' is not registered.")
        return cast(T, self._providers[cls.identifier])

    @property
    def storage(self) -> StorageProvider:
        return self.get(StorageProvider)

    @property
    def event_bus(self) -> EventBusProvider:
        return self.get(EventBusProvider)

    @property
    def caching(self) -> CachingProvider:
        return self.get(CachingProvider)

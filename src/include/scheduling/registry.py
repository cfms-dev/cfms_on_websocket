"""In-memory registry of trusted scheduled task implementations."""

from collections.abc import Iterable
from typing import Any

from pydantic import BaseModel

from include.scheduling.contracts import ScheduledTaskRegistration


class ScheduledTaskRegistry:
    """Resolve task names and validate payloads against their registered version.

    Core registrations are loaded first and extension registrations are appended.
    Rejecting duplicate names prevents an extension from replacing another
    owner's executable code.
    """

    def __init__(self, registrations: Iterable[ScheduledTaskRegistration[Any]] = ()):
        """Create a registry and validate uniqueness of initial registrations."""

        self._registrations: dict[str, ScheduledTaskRegistration[Any]] = {}
        for registration in registrations:
            self.register(registration)

    def register(self, registration: ScheduledTaskRegistration[Any]) -> None:
        """Add one task type, rejecting a name already owned by the registry."""

        if registration.name in self._registrations:
            raise ValueError(f"Duplicate scheduled task type {registration.name!r}")
        self._registrations[registration.name] = registration

    def get(self, name: str) -> ScheduledTaskRegistration[Any] | None:
        """Return the current executable contract for ``name``, if registered."""

        return self._registrations.get(name)

    def all(self) -> tuple[ScheduledTaskRegistration[Any], ...]:
        """Return registrations in deterministic insertion order."""

        return tuple(self._registrations.values())

    def validate_payload(
        self, name: str, contract_version: int, payload: object
    ) -> BaseModel:
        """Validate a persisted payload against the exact registered contract.

        A missing name or version mismatch is an unavailable executable contract,
        not a payload validation error.  Pydantic validation errors intentionally
        propagate to the caller.
        """

        registration = self.get(name)
        if registration is None:
            raise LookupError(f"Scheduled task type {name!r} is not registered")
        if registration.contract_version != contract_version:
            raise LookupError(
                f"Scheduled task type {name!r} contract version is unavailable"
            )
        return registration.payload_model.model_validate(payload)

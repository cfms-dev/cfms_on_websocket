from collections.abc import Iterable

from pydantic import BaseModel

from include.scheduling.contracts import ScheduledTaskRegistration


class ScheduledTaskRegistry:
    def __init__(self, registrations: Iterable[ScheduledTaskRegistration] = ()):
        self._registrations: dict[str, ScheduledTaskRegistration] = {}
        for registration in registrations:
            self.register(registration)

    def register(self, registration: ScheduledTaskRegistration) -> None:
        if registration.name in self._registrations:
            raise ValueError(f"Duplicate scheduled task type {registration.name!r}")
        self._registrations[registration.name] = registration

    def get(self, name: str) -> ScheduledTaskRegistration | None:
        return self._registrations.get(name)

    def all(self) -> tuple[ScheduledTaskRegistration, ...]:
        return tuple(self._registrations.values())

    def validate_payload(
        self, name: str, contract_version: int, payload: object
    ) -> BaseModel:
        registration = self.get(name)
        if registration is None:
            raise LookupError(f"Scheduled task type {name!r} is not registered")
        if registration.contract_version != contract_version:
            raise LookupError(
                f"Scheduled task type {name!r} contract version is unavailable"
            )
        return registration.payload_model.model_validate(payload)

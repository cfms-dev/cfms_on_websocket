from dataclasses import dataclass
from typing import Annotated, Literal, Self

from pydantic import (
    BaseModel,
    ConfigDict,
    Field,
    FiniteFloat,
    StringConstraints,
    ValidationError,
    model_validator,
)
from sqlalchemy.orm import Session as OrmSession

from include.database.clock import database_now
from include.database.session import Session
from include.database.system_states import (
    StoredSystemState,
    create_system_state,
    delete_system_state,
    read_system_state,
    update_system_state,
)
from include.domains.operations.lockdown.contracts import (
    LockdownSource,
    LockdownState,
    ScheduledLockdownActivation,
    _LockdownStateBase,
)

_LOCKDOWN_OWNER = "core"
_LOCKDOWN_STATE_KEY = "lockdown"
_LOCKDOWN_LEGACY_SCHEMA_VERSION = 1
_LOCKDOWN_SCHEMA_VERSION = 2
_LOCKDOWN_ACTIVATION_STATE_KEY = "lockdown_activation"
_LOCKDOWN_ACTIVATION_LEGACY_SCHEMA_VERSION = 1
_LOCKDOWN_ACTIVATION_SCHEMA_VERSION = 2

_PersistedLockdownSource = Literal["manual", "scheduled", "automatic"]


class _LockdownPayloadV1(_LockdownStateBase):
    last_disabled_at: Annotated[
        FiniteFloat,
        Field(ge=0),
    ]


class _LockdownPayload(_LockdownPayloadV1):
    source: _PersistedLockdownSource | None

    @model_validator(mode="after")
    def _validate_source(self) -> Self:
        if self.enabled and self.source is None:
            raise ValueError("An enabled lockdown requires a source")
        if not self.enabled and self.source is not None:
            raise ValueError("A disabled lockdown cannot have a source")
        return self


class _LockdownActivationBase(BaseModel):
    model_config = ConfigDict(
        frozen=True,
        strict=True,
        extra="forbid",
    )

    activation_id: Annotated[
        str,
        StringConstraints(min_length=1, max_length=128),
    ]
    lockdown_revision: Annotated[int, Field(gt=0)]


class _LockdownActivationPayloadV1(_LockdownActivationBase):
    expires_at: Annotated[FiniteFloat, Field(ge=0)]


class _LockdownActivationPayload(_LockdownActivationBase):
    expires_at: Annotated[FiniteFloat, Field(ge=0)] | None


@dataclass(frozen=True, slots=True)
class _StoredLockdownState:
    state: LockdownState
    source: LockdownSource | None
    last_disabled_at: float
    revision: int


@dataclass(frozen=True, slots=True)
class _StoredLockdownActivation:
    payload: _LockdownActivationPayload
    revision: int


def _parse_lockdown_state(
    stored: StoredSystemState,
) -> _StoredLockdownState:
    if stored.schema_version == _LOCKDOWN_LEGACY_SCHEMA_VERSION:
        payload = _LockdownPayloadV1.model_validate(stored.payload)
        source = LockdownSource.UNKNOWN if payload.enabled else None
    elif stored.schema_version == _LOCKDOWN_SCHEMA_VERSION:
        payload = _LockdownPayload.model_validate(stored.payload)
        source = None if payload.source is None else LockdownSource(payload.source)
    else:
        raise RuntimeError(
            f"Unsupported lockdown state schema version: {stored.schema_version}"
        )

    return _StoredLockdownState(
        state=LockdownState(
            enabled=payload.enabled,
            reason=payload.reason,
        ),
        source=source,
        last_disabled_at=payload.last_disabled_at,
        revision=stored.revision,
    )


def _read_lockdown_state(
    session: OrmSession,
) -> _StoredLockdownState | None:
    try:
        stored = read_system_state(
            session,
            _LOCKDOWN_OWNER,
            _LOCKDOWN_STATE_KEY,
        )
        return None if stored is None else _parse_lockdown_state(stored)
    except ValidationError as exc:
        raise RuntimeError("Invalid persisted lockdown state") from exc


def _read_lockdown_activation(
    session: OrmSession,
) -> _StoredLockdownActivation | None:
    try:
        stored = read_system_state(
            session,
            _LOCKDOWN_OWNER,
            _LOCKDOWN_ACTIVATION_STATE_KEY,
        )
        if stored is None:
            return None
        if stored.schema_version == _LOCKDOWN_ACTIVATION_LEGACY_SCHEMA_VERSION:
            legacy = _LockdownActivationPayloadV1.model_validate(stored.payload)
            payload = _LockdownActivationPayload(
                activation_id=legacy.activation_id,
                expires_at=legacy.expires_at,
                lockdown_revision=legacy.lockdown_revision,
            )
        elif stored.schema_version == _LOCKDOWN_ACTIVATION_SCHEMA_VERSION:
            payload = _LockdownActivationPayload.model_validate(stored.payload)
        else:
            raise RuntimeError(
                "Unsupported lockdown activation schema version: "
                f"{stored.schema_version}"
            )
        return _StoredLockdownActivation(
            payload=payload,
            revision=stored.revision,
        )
    except ValidationError as exc:
        raise RuntimeError("Invalid persisted lockdown activation") from exc


def _valid_lockdown_activation(
    state: _StoredLockdownState | None,
    activation: _StoredLockdownActivation | None,
) -> _LockdownActivationPayload | None:
    if (
        state is None
        or not state.state.enabled
        or activation is None
        or activation.payload.lockdown_revision != state.revision
        or state.source not in (LockdownSource.SCHEDULED, LockdownSource.UNKNOWN)
    ):
        return None
    return activation.payload


def _lockdown_source(
    state: _StoredLockdownState | None,
    activation: _LockdownActivationPayload | None,
) -> LockdownSource | None:
    if state is None or not state.state.enabled:
        return None
    if state.source is LockdownSource.UNKNOWN and activation is not None:
        return LockdownSource.SCHEDULED
    if state.source is LockdownSource.SCHEDULED and activation is None:
        return LockdownSource.UNKNOWN
    return state.source


class LockdownStateManager:
    def get_state(self) -> LockdownState:
        with Session() as session:
            stored = _read_lockdown_state(session)

        return LockdownState() if stored is None else stored.state

    def get_last_disabled_at(self) -> float:
        with Session() as session:
            stored = _read_lockdown_state(session)

        return 0.0 if stored is None else stored.last_disabled_at

    def get_source(self) -> LockdownSource | None:
        with Session() as session:
            state = _read_lockdown_state(session)
            activation = _valid_lockdown_activation(
                state,
                _read_lockdown_activation(session),
            )

        return _lockdown_source(state, activation)

    def get_scheduled_activation(self) -> ScheduledLockdownActivation | None:
        with Session() as session:
            state = _read_lockdown_state(session)
            activation = _valid_lockdown_activation(
                state,
                _read_lockdown_activation(session),
            )
            observed_at = database_now(session)

        if activation is None:
            return None
        return ScheduledLockdownActivation(
            activation_id=activation.activation_id,
            expires_at=activation.expires_at,
            observed_at=observed_at,
        )


lockdown_state_manager = LockdownStateManager()


class _LockdownCasConflict(RuntimeError):
    pass


def _persist_lockdown_state(
    session: OrmSession,
    current: _StoredLockdownState | None,
    state: LockdownState,
    source: LockdownSource | None,
    last_disabled_at: float,
) -> int:
    payload = _LockdownPayload(
        enabled=state.enabled,
        reason=state.reason,
        source=None if source is None else source.value,
        last_disabled_at=last_disabled_at,
    ).model_dump(mode="json")
    if current is None:
        applied = create_system_state(
            session,
            _LOCKDOWN_OWNER,
            _LOCKDOWN_STATE_KEY,
            schema_version=_LOCKDOWN_SCHEMA_VERSION,
            payload=payload,
        )
        revision = 1
    else:
        applied = update_system_state(
            session,
            _LOCKDOWN_OWNER,
            _LOCKDOWN_STATE_KEY,
            expected_revision=current.revision,
            schema_version=_LOCKDOWN_SCHEMA_VERSION,
            payload=payload,
        )
        revision = current.revision + 1
    if not applied:
        raise _LockdownCasConflict
    return revision


def _persist_lockdown_activation(
    session: OrmSession,
    current: _StoredLockdownActivation | None,
    payload: _LockdownActivationPayload,
) -> None:
    values = payload.model_dump(mode="json")
    if current is None:
        applied = create_system_state(
            session,
            _LOCKDOWN_OWNER,
            _LOCKDOWN_ACTIVATION_STATE_KEY,
            schema_version=_LOCKDOWN_ACTIVATION_SCHEMA_VERSION,
            payload=values,
        )
    else:
        applied = update_system_state(
            session,
            _LOCKDOWN_OWNER,
            _LOCKDOWN_ACTIVATION_STATE_KEY,
            expected_revision=current.revision,
            schema_version=_LOCKDOWN_ACTIVATION_SCHEMA_VERSION,
            payload=values,
        )
    if not applied:
        raise _LockdownCasConflict


def _delete_lockdown_activation(
    session: OrmSession,
    current: _StoredLockdownActivation | None,
) -> bool:
    if current is None:
        return False
    if not delete_system_state(
        session,
        _LOCKDOWN_OWNER,
        _LOCKDOWN_ACTIVATION_STATE_KEY,
        expected_revision=current.revision,
    ):
        raise _LockdownCasConflict
    return True

import secrets
import time
from typing import Any

from sqlalchemy import (
    JSON,
    VARCHAR,
    BigInteger,
    Boolean,
    CheckConstraint,
    Double,
    ForeignKey,
    Index,
    Integer,
    UniqueConstraint,
)
from sqlalchemy.orm import Mapped, mapped_column

from include.database.session import Base


class Schedule(Base):
    __tablename__ = "schedules"
    __table_args__ = (
        CheckConstraint("revision > 0", name="ck_schedules_revision_positive"),
        CheckConstraint(
            "task_contract_version > 0",
            name="ck_schedules_task_contract_version_positive",
        ),
        CheckConstraint(
            "trigger_type IN ('cron', 'date', 'interval')",
            name="ck_schedules_trigger_type",
        ),
        CheckConstraint(
            "status IN ('active', 'completed', 'failed', 'deleted')",
            name="ck_schedules_status",
        ),
        Index("ix_schedules_due", "enabled", "status", "next_run_at"),
    )

    id: Mapped[str] = mapped_column(
        VARCHAR(32), primary_key=True, default=lambda: secrets.token_hex(16)
    )
    task_name: Mapped[str] = mapped_column(VARCHAR(255), nullable=False)
    task_contract_version: Mapped[int] = mapped_column(Integer, nullable=False)
    payload: Mapped[dict[str, Any]] = mapped_column(JSON, nullable=False)
    trigger_type: Mapped[str] = mapped_column(VARCHAR(16), nullable=False)
    trigger_data: Mapped[dict[str, Any]] = mapped_column(JSON, nullable=False)
    timezone: Mapped[str] = mapped_column(VARCHAR(255), nullable=False)
    enabled: Mapped[bool] = mapped_column(Boolean, nullable=False, default=True)
    status: Mapped[str] = mapped_column(VARCHAR(16), nullable=False, default="active")
    revision: Mapped[int] = mapped_column(BigInteger, nullable=False, default=1)
    next_run_at: Mapped[float | None] = mapped_column(Double, nullable=True)
    active_execution_id: Mapped[str | None] = mapped_column(VARCHAR(64), nullable=True)
    pending_scheduled_for: Mapped[float | None] = mapped_column(Double, nullable=True)
    created_by: Mapped[str] = mapped_column(
        ForeignKey("users.username"), nullable=False
    )
    created_at: Mapped[float] = mapped_column(Double, nullable=False, default=time.time)
    updated_by: Mapped[str] = mapped_column(
        ForeignKey("users.username"), nullable=False
    )
    updated_at: Mapped[float] = mapped_column(Double, nullable=False, default=time.time)
    deleted_at: Mapped[float | None] = mapped_column(Double, nullable=True)


class ScheduleExecution(Base):
    __tablename__ = "schedule_executions"
    __table_args__ = (
        UniqueConstraint(
            "schedule_id", "scheduled_for", name="uq_schedule_executions_occurrence"
        ),
        CheckConstraint("attempt >= 0", name="ck_schedule_executions_attempt"),
        CheckConstraint(
            "state IN ('pending', 'running', 'retry_wait', 'succeeded', 'failed')",
            name="ck_schedule_executions_state",
        ),
        CheckConstraint(
            "dispatch_state IN ('pending', 'sent')",
            name="ck_schedule_executions_dispatch_state",
        ),
        Index(
            "ix_schedule_executions_claim",
            "state",
            "dispatch_state",
            "retry_at",
            "lease_expires_at",
        ),
    )

    id: Mapped[str] = mapped_column(VARCHAR(64), primary_key=True)
    schedule_id: Mapped[str] = mapped_column(
        ForeignKey("schedules.id", ondelete="CASCADE"), nullable=False, index=True
    )
    provider_generation: Mapped[int] = mapped_column(
        BigInteger, nullable=False, default=1
    )
    scheduled_for: Mapped[float] = mapped_column(Double, nullable=False)
    state: Mapped[str] = mapped_column(VARCHAR(16), nullable=False, default="pending")
    dispatch_state: Mapped[str] = mapped_column(
        VARCHAR(16), nullable=False, default="pending"
    )
    attempt: Mapped[int] = mapped_column(Integer, nullable=False, default=0)
    retry_at: Mapped[float | None] = mapped_column(Double, nullable=True)
    lease_owner: Mapped[str | None] = mapped_column(VARCHAR(64), nullable=True)
    lease_expires_at: Mapped[float | None] = mapped_column(Double, nullable=True)
    started_at: Mapped[float | None] = mapped_column(Double, nullable=True)
    completed_at: Mapped[float | None] = mapped_column(Double, nullable=True)
    result: Mapped[dict[str, Any] | None] = mapped_column(JSON, nullable=True)
    error: Mapped[str | None] = mapped_column(VARCHAR(1024), nullable=True)
    created_at: Mapped[float] = mapped_column(Double, nullable=False, default=time.time)


class SchedulingRuntimeState(Base):
    __tablename__ = "scheduling_runtime_state"
    __table_args__ = (
        CheckConstraint("id = 1", name="ck_scheduling_runtime_state_singleton"),
        CheckConstraint("generation > 0", name="ck_scheduling_generation_positive"),
        CheckConstraint(
            "provider IN ('local', 'redis')", name="ck_scheduling_runtime_provider"
        ),
    )

    id: Mapped[int] = mapped_column(Integer, primary_key=True, default=1)
    provider: Mapped[str] = mapped_column(VARCHAR(16), nullable=False)
    generation: Mapped[int] = mapped_column(BigInteger, nullable=False, default=1)
    schema_version: Mapped[int] = mapped_column(Integer, nullable=False, default=1)
    updated_at: Mapped[float] = mapped_column(Double, nullable=False, default=time.time)

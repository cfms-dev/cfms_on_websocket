__all__ = ["OffsetPaginationRequest", "PermissionEntry"]

from typing import Self

from pydantic import model_validator

from include.domains.pagination import PaginationOffset, PaginationPageSize
from include.transport.request_handler import (
    REQUEST_UNSET,
    Omittable,
    RequestDataModel,
)


class OffsetPaginationRequest(RequestDataModel):
    offset: Omittable[PaginationOffset] = REQUEST_UNSET
    count: Omittable[PaginationPageSize] = REQUEST_UNSET


class PermissionEntry(RequestDataModel):
    permission: str
    granted: bool
    start_time: float
    end_time: float | None

    @model_validator(mode="after")
    def validate_time_window(self) -> Self:
        if self.end_time is not None and self.end_time < self.start_time:
            raise ValueError("end_time must not be earlier than start_time")
        return self

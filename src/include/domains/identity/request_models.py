__all__ = ["OffsetPaginationRequest", "TimedPermission"]

from include.domains.pagination import PaginationOffset, PaginationPageSize
from include.transport.request_handler import (
    REQUEST_UNSET,
    Omittable,
    RequestDataModel,
)


class OffsetPaginationRequest(RequestDataModel):
    offset: Omittable[PaginationOffset] = REQUEST_UNSET
    count: Omittable[PaginationPageSize] = REQUEST_UNSET


class TimedPermission(RequestDataModel):
    permission: str
    start_time: float
    end_time: Omittable[float] = REQUEST_UNSET

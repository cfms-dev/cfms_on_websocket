from tests.support.assertions import assert_error, assert_success

__all__ = ["assert_error", "assert_success", "permission_entry"]


def permission_entry(
    permission: str,
    *,
    granted: bool = True,
    start_time: float = 0.0,
    end_time: float | None = None,
) -> dict[str, str | bool | float | None]:
    return {
        "permission": permission,
        "granted": granted,
        "start_time": start_time,
        "end_time": end_time,
    }

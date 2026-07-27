from typing import Any

from include.transport.connection import ConnectionHandler
from include.transport.request_handler import Result


def respond_to_node_name_conflict(
    handler: ConnectionHandler,
    payload: dict[str, Any],
    message: str,
    *,
    target: str,
    result_data: dict[str, Any],
) -> Result:
    payload.pop("entity", None)
    handler.conclude_request(409, payload, message)
    if "duplicate_id" in payload:
        result_data = {**result_data, "duplicate_id": payload["duplicate_id"]}
    return Result(
        code=409,
        target=target,
        data=result_data,
        username=handler.username,
    )

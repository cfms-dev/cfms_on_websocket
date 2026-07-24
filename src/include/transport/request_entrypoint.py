from http import HTTPStatus

from websockets import Headers, Request, Response
from websockets.sync.server import ServerConnection

from include.domains.security.guards.login import LoginGuard
from include.transport.client_address import get_client_ip


def global_process_request(
    connection: ServerConnection, request: Request
) -> Response | None:
    ip = get_client_ip(connection)

    if not LoginGuard.evaluate_subnet_access(ip).allowed:
        response_headers = Headers()
        response_headers["Content-Type"] = "text/plain"
        return Response(
            status_code=HTTPStatus.FORBIDDEN,
            reason_phrase="Forbidden",
            headers=response_headers,
            body=b"IP address is not permitted.",
        )

    return None

from pydantic import ConfigDict

from include.database.models.identity import User
from include.database.session import Session
from include.domains.access.permissions import Permissions
from include.messages import Messages as smsg
from include.transport.request_handler import RequestDataModel, RequestHandler, Result


class _DebugRequest(RequestDataModel):
    model_config = ConfigDict(extra="allow")


class RequestThrowExceptionHandler(RequestHandler[_DebugRequest]):
    """A request handler that always throws an exception for testing purposes."""

    request_model = _DebugRequest
    requires_auth = True
    rate_limit_cost = 3

    def handle(self, handler, request):
        """Handle the request by throwing an exception."""

        with Session() as session:
            user = User.get_existing(session, handler.user_id)

            if Permissions.DEBUGGING not in user.all_permissions:
                handler.conclude_request(403, {}, smsg.USER_LACKS_DEBUGGING_PERMISSION)
                return Result(code=403, target=None, user_id=handler.user_id)

        raise RuntimeError(
            "This is a test exception thrown by RequestThrowExceptionHandler."
        )

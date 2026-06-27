from include.database.session import Session
from include.domains.access.permissions import Permissions
from include.domains.identity.models import User
from include.domains.operations.messages import Messages as smsg
from include.transport.connection import ConnectionHandler
from include.transport.request_handler import RequestHandler


class RequestThrowExceptionHandler(RequestHandler):
    """A request handler that always throws an exception for testing purposes."""

    require_auth = True

    def handle(self, handler: "ConnectionHandler"):
        """Handle the request by throwing an exception."""

        with Session() as session:
            user = User.get_existing(session, handler.username)

            if Permissions.DEBUGGING not in user.all_permissions:
                handler.conclude_request(403, {}, smsg.USER_LACKS_DEBUGGING_PERMISSION)
                return 403, None, handler.username

        raise Exception(
            "This is a test exception thrown by RequestThrowExceptionHandler."
        )

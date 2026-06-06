from include.classes.connection_handler import ConnectionHandler
from include.classes.enum.permissions import Permissions
from include.database.handler import Session
from include.database.models.classic import User
from include.handlers.base import RequestHandler
from include.system.messages import Messages as smsg


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

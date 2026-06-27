from include.database.session import Session
from include.domains.access.permissions import Permissions
from include.domains.documents import Document, DocumentRevision
from include.domains.documents.handlers.documents import (
    create_file_task,
    mark_document_modified,
)
from include.domains.identity.models import User
from include.domains.operations.messages import Messages as smsg
from include.transport.connection import ConnectionHandler
from include.transport.request_handler import RequestHandler


class RequestListRevisionsHandler(RequestHandler):
    schema = {
        "type": "object",
        "properties": {
            "document_id": {"type": "string", "minLength": 1},
        },
        "required": ["document_id"],
        "additionalProperties": False,
    }

    require_auth = True  # when True, handler.username is guaranteed to be not None

    def handle(self, handler: ConnectionHandler):
        document_id = handler.data["document_id"]

        with Session() as session:
            user = User.get_existing(session, handler.username)
            document = session.get(Document, document_id)

            if document is None:
                handler.conclude_request(404, {}, "Document not found")
                return 404, document_id, handler.username

            if (
                Permissions.LIST_REVISIONS not in user.all_permissions
                or not document.check_access_requirements(user, "read")
            ):
                handler.conclude_request(403, {}, smsg.ACCESS_DENIED)
                return 403, document_id, handler.username

            revisions = [
                {
                    "id": rev.id,
                    "parent_id": rev.parent_revision_id,
                    "created_time": rev.created_time,
                    "is_current": rev.id == document.current_revision_id,
                }
                for rev in document.revisions
            ]

        handler.conclude_request(
            200, {"revisions": revisions}, "Revisions listed successfully"
        )
        return 200, document_id, handler.username


class RequestGetRevisionHandler(RequestHandler):
    schema = {
        "type": "object",
        "properties": {
            "id": {"type": "string", "minLength": 1, "maxLength": 64},
        },
        "required": ["id"],
        "additionalProperties": False,
    }

    require_auth = True  # when True, handler.username is guaranteed to be not None

    def handle(self, handler: ConnectionHandler):
        revision_id = handler.data["id"]

        with Session() as session:
            user = User.get_existing(session, handler.username)
            revision = session.get(DocumentRevision, revision_id)

            if revision is None:
                handler.conclude_request(404, {}, "Revision not found")
                return 404, revision_id, handler.username

            if (
                Permissions.VIEW_REVISION not in user.all_permissions
                or not revision.document.check_access_requirements(user, "read")
            ):
                handler.conclude_request(403, {}, smsg.ACCESS_DENIED)
                return 403, revision_id, handler.username

            task_data = create_file_task(revision.file)

        handler.conclude_request(200, {"task_data": task_data}, smsg.SUCCESS)
        return 200, revision_id, handler.username


class RequestSetDocumentRevisionHandler(RequestHandler):
    schema = {
        "type": "object",
        "properties": {
            "document_id": {"type": "string", "minLength": 1},
            "revision_id": {"type": "string", "minLength": 1, "maxLength": 64},
        },
        "required": ["document_id", "revision_id"],
        "additionalProperties": False,
    }

    require_auth = True  # when True, handler.username is guaranteed to be not None

    def handle(self, handler: ConnectionHandler):
        document_id = handler.data["document_id"]
        revision_id = handler.data["revision_id"]

        with Session() as session:
            user = User.get_existing(session, handler.username)
            document = session.get(Document, document_id)
            revision = session.get(DocumentRevision, revision_id)

            if (
                document is None
                or revision is None
                or revision.document_id != document.id
            ):
                handler.conclude_request(404, {}, "Document or Revision not found")
                return 404, document_id, handler.username

            if (
                Permissions.SET_CURRENT_REVISION not in user.all_permissions
                or not document.check_access_requirements(user, "write")
            ):
                handler.conclude_request(403, {}, smsg.ACCESS_DENIED)
                return 403, document_id, handler.username

            document.current_revision_id = revision.id
            mark_document_modified(document, user.username)
            session.commit()

        handler.conclude_request(200, {}, "Current revision set successfully")
        return 200, document_id, handler.username


class RequestDeleteRevisionHandler(RequestHandler):
    schema = {
        "type": "object",
        "properties": {
            "id": {"type": "string", "minLength": 1, "maxLength": 64},
        },
        "required": ["id"],
        "additionalProperties": False,
    }

    require_auth = True

    def handle(self, handler: ConnectionHandler):
        ### be careful! this function will change the tree structure of revisions ###

        revision_id = handler.data["id"]

        with Session() as session:
            user = User.get_existing(session, handler.username)
            revision = session.get(DocumentRevision, revision_id)

            if revision is None:
                handler.conclude_request(404, {}, "Revision not found")
                return 404, revision_id, handler.username

            document = revision.document
            if (
                document.current_revision_id == revision.id
                or len(document.revisions) == 1  # backward compatibility
            ):
                handler.conclude_request(400, {}, "Cannot delete the current revision")
                return 400, revision_id, handler.username

            if (
                Permissions.DELETE_REVISION not in user.all_permissions
                or document.check_access_requirements(user, "write") is False
            ):
                handler.conclude_request(403, {}, smsg.ACCESS_DENIED)
                return 403, revision_id, handler.username

            # Try to connect parent and child revisions directly
            for child_rev in revision.child_revisions:
                child_rev.parent_revision = revision.parent_revision

            revision.before_delete()
            mark_document_modified(document, user.username)
            session.delete(revision)
            session.commit()

        handler.conclude_request(200, {}, "Revision deleted successfully")
        return 200, revision_id, handler.username

from sqlalchemy import and_, or_

from include.database.models.documents import Document, DocumentRevision
from include.database.models.identity import User
from include.database.session import Session
from include.domains.access.permissions import Permissions
from include.domains.documents.handlers.documents import (
    create_file_task,
    mark_document_modified,
)
from include.domains.pagination import (
    CURSOR_PAGINATION_SCHEMA,
    CursorError,
    decode_cursor,
    get_page_size,
    make_cursor_response,
)
from include.messages import Messages as smsg
from include.transport.connection import ConnectionHandler
from include.transport.request_handler import RequestHandler, Result


class RequestListRevisionsHandler(RequestHandler):
    schema = {
        "type": "object",
        "properties": {
            "document_id": {"type": "string", "minLength": 1},
            **CURSOR_PAGINATION_SCHEMA,
        },
        "required": ["document_id"],
        "additionalProperties": False,
    }

    require_auth = True  # when True, handler.username is guaranteed to be not None

    def handle(self, handler: ConnectionHandler):
        document_id = handler.data["document_id"]
        page_size = get_page_size(handler.data)
        cursor = handler.data.get("cursor")

        with Session() as session:
            user = User.get_existing(session, handler.username)
            document = session.get(Document, document_id)

            if document is None:
                handler.conclude_request(404, {}, "Document not found")
                return Result(code=404, target=document_id, username=handler.username)

            if (
                Permissions.LIST_REVISIONS not in user.all_permissions
                or not document.check_access_requirements(user, "read")
            ):
                handler.conclude_request(403, {}, smsg.ACCESS_DENIED)
                return Result(code=403, target=document_id, username=handler.username)

            filters = {"document_id": document_id}
            sort = "created_time_id:asc"
            try:
                last_key = decode_cursor(
                    cursor,
                    action="list_revisions",
                    sort=sort,
                    filters=filters,
                    value_types=[(int, float), str],
                )
            except CursorError as exc:
                handler.conclude_request(400, {}, str(exc))
                return Result(code=400, target=document_id, username=handler.username)

            revisions_query = session.query(DocumentRevision).filter(
                DocumentRevision.document_id == document_id
            )
            if last_key is not None:
                last_created_time, last_id = last_key
                revisions_query = revisions_query.filter(
                    or_(
                        DocumentRevision.created_time > last_created_time,
                        and_(
                            DocumentRevision.created_time == last_created_time,
                            DocumentRevision.id > last_id,
                        ),
                    )
                )

            queried_revisions = (
                revisions_query.order_by(
                    DocumentRevision.created_time.asc(), DocumentRevision.id.asc()
                )
                .limit(page_size + 1)
                .all()
            )
            revisions = [
                {
                    "id": rev.id,
                    "parent_id": rev.parent_revision_id,
                    "created_time": rev.created_time,
                    "is_current": rev.id == document.current_revision_id,
                }
                for rev in queried_revisions
            ]

            response_data = make_cursor_response(
                revisions,
                page_size=page_size,
                action="list_revisions",
                sort=sort,
                filters=filters,
                cursor_key=lambda item: [item["created_time"], item["id"]],
            )

        handler.conclude_request(200, response_data, "Revisions listed successfully")
        return Result(code=200, target=document_id, username=handler.username)


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
                return Result(code=404, target=revision_id, username=handler.username)

            if (
                Permissions.VIEW_REVISION not in user.all_permissions
                or not revision.document.check_access_requirements(user, "read")
            ):
                handler.conclude_request(403, {}, smsg.ACCESS_DENIED)
                return Result(code=403, target=revision_id, username=handler.username)

            task_data = create_file_task(revision.file)

        handler.conclude_request(200, {"task_data": task_data}, smsg.SUCCESS)
        return Result(code=200, target=revision_id, username=handler.username)


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
                return Result(code=404, target=document_id, username=handler.username)

            if (
                Permissions.SET_CURRENT_REVISION not in user.all_permissions
                or not document.check_access_requirements(user, "write")
            ):
                handler.conclude_request(403, {}, smsg.ACCESS_DENIED)
                return Result(code=403, target=document_id, username=handler.username)

            document.current_revision_id = revision.id
            mark_document_modified(document, user.username)
            session.commit()

        handler.conclude_request(200, {}, "Current revision set successfully")
        return Result(code=200, target=document_id, username=handler.username)


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
        # Be careful: this function changes the revision tree structure.

        revision_id = handler.data["id"]

        with Session() as session:
            user = User.get_existing(session, handler.username)
            revision = session.get(DocumentRevision, revision_id)

            if revision is None:
                handler.conclude_request(404, {}, "Revision not found")
                return Result(code=404, target=revision_id, username=handler.username)

            document = revision.document
            if (
                document.current_revision_id == revision.id
                or len(document.revisions) == 1  # backward compatibility
            ):
                handler.conclude_request(400, {}, "Cannot delete the current revision")
                return Result(code=400, target=revision_id, username=handler.username)

            if (
                Permissions.DELETE_REVISION not in user.all_permissions
                or document.check_access_requirements(user, "write") is False
            ):
                handler.conclude_request(403, {}, smsg.ACCESS_DENIED)
                return Result(code=403, target=revision_id, username=handler.username)

            with session.no_autoflush:
                # Try to connect parent and child revisions directly
                for child_rev in revision.child_revisions:
                    child_rev.parent_revision = revision.parent_revision

                revision.before_delete()
                mark_document_modified(document, user.username)
                session.delete(revision)
            session.commit()

        handler.conclude_request(200, {}, "Revision deleted successfully")
        return Result(code=200, target=revision_id, username=handler.username)

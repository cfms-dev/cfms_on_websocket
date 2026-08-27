from sqlalchemy import and_, or_

from include.database.models.documents import Document, DocumentRevision
from include.database.models.identity import User
from include.database.session import Session
from include.domains.access.authorization.evaluation import check_access_requirements
from include.domains.access.permissions import Permissions
from include.domains.documents.commands.file_tasks import cancel_file_tasks_for_files
from include.domains.documents.commands.revision_deletion import (
    delete_revision_and_unreferenced_file,
)
from include.domains.documents.download_limits import check_download_issue_limits
from include.domains.documents.file_task_signals import publish_cancelled_file_tasks
from include.domains.documents.handlers.documents import (
    create_file_task,
    mark_document_modified,
)
from include.domains.documents.queries.file_references import (
    find_unreachable_revision_file_ids,
)
from include.domains.documents.types import RevisionID
from include.domains.pagination import (
    CursorError,
    PaginationCursor,
    PaginationCursorToken,
    PaginationPageSize,
    get_page_size,
    make_cursor_response,
)
from include.domains.security.guards.rate_limits import risk_control_transaction
from include.messages import Messages as smsg
from include.transport.connection import ConnectionHandler
from include.transport.request_handler import (
    REQUEST_UNSET,
    Omittable,
    RequestDataModel,
    RequestHandler,
    Result,
)
from include.types import NonEmptyString


class _ListRevisionsRequest(RequestDataModel):
    document_id: NonEmptyString
    page_size: Omittable[PaginationPageSize] = REQUEST_UNSET
    cursor: PaginationCursorToken | None = None


class _RevisionIDRequest(RequestDataModel):
    id: RevisionID


class _SetDocumentRevisionRequest(RequestDataModel):
    document_id: NonEmptyString
    revision_id: RevisionID


class RequestListRevisionsHandler(RequestHandler):
    request_model = _ListRevisionsRequest

    require_auth = True  # when True, handler.username is guaranteed to be not None
    rate_limit_cost = 2

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
                or not check_access_requirements(session, document, user, "read")
            ):
                handler.conclude_request(403, {}, smsg.ACCESS_DENIED)
                return Result(code=403, target=document_id, username=handler.username)

            filters = {"document_id": document_id}
            sort = "created_time_id:asc"
            try:
                decoded_cursor = PaginationCursor.decode(
                    cursor,
                    action="list_revisions",
                    sort=sort,
                    filters=filters,
                    value_types=[(int, float), str],
                )
                last_key = None if decoded_cursor is None else decoded_cursor.last
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
    request_model = _RevisionIDRequest

    require_auth = True  # when True, handler.username is guaranteed to be not None
    rate_limit_cost = 3

    def handle(self, handler: ConnectionHandler):
        revision_id = handler.data["id"]

        with Session() as session, risk_control_transaction(session):
            user = User.get_existing(session, handler.username)
            revision = session.get(DocumentRevision, revision_id)

            if revision is None:
                response_code = result_code = 404
                data = {}
                message = "Revision not found"
            elif (
                Permissions.VIEW_REVISION not in user.all_permissions
                or not check_access_requirements(
                    session, revision.document, user, "read"
                )
            ):
                response_code = result_code = 403
                data = {}
                message = smsg.ACCESS_DENIED
            else:
                limit_decision = check_download_issue_limits(
                    session,
                    user.username,
                    handler.remote_address,
                    account_created_at=user.created_time,
                    bypass_rate_limit=(
                        Permissions.BYPASS_DOCUMENT_DOWNLOAD_RATE_LIMIT
                        in user.all_permissions
                    ),
                )
                if not limit_decision.allowed:
                    response_code = result_code = 429
                    data = {
                        "scope": limit_decision.scope,
                        "limit": limit_decision.limit,
                        "retry_after_seconds": limit_decision.retry_after_seconds,
                    }
                    message = "Download request limit exceeded. Please try again later."
                else:
                    task_data = create_file_task(
                        session,
                        revision.file,
                        issued_by_username=user.username,
                    )
                    response_code = result_code = 200
                    data = {"task_data": task_data}
                    message = smsg.SUCCESS

        handler.conclude_request(response_code, data, message)
        return Result(
            code=result_code,
            target=revision_id,
            data=data if result_code == 429 else None,
            username=handler.username,
        )


class RequestSetDocumentRevisionHandler(RequestHandler):
    request_model = _SetDocumentRevisionRequest

    require_auth = True  # when True, handler.username is guaranteed to be not None
    rate_limit_cost = 3

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
                or not check_access_requirements(session, document, user, "write")
            ):
                handler.conclude_request(403, {}, smsg.ACCESS_DENIED)
                return Result(code=403, target=document_id, username=handler.username)

            document.current_revision_id = revision.id
            mark_document_modified(document, user.username)
            session.commit()

        handler.conclude_request(200, {}, "Current revision set successfully")
        return Result(code=200, target=document_id, username=handler.username)


class RequestDeleteRevisionHandler(RequestHandler):
    request_model = _RevisionIDRequest

    require_auth = True
    rate_limit_cost = 5

    def handle(self, handler: ConnectionHandler):
        # Be careful: this function changes the revision tree structure.

        revision_id = handler.data["id"]

        cancelled_task_ids: list[str] = []
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
                or check_access_requirements(session, document, user, "write") is False
            ):
                handler.conclude_request(403, {}, smsg.ACCESS_DENIED)
                return Result(code=403, target=revision_id, username=handler.username)

            with session.no_autoflush:
                # Try to connect parent and child revisions directly
                for child_rev in revision.child_revisions:
                    child_rev.parent_revision = revision.parent_revision

                unreachable_file_ids = find_unreachable_revision_file_ids(
                    session, [revision_id]
                )
                cancelled_task_ids = cancel_file_tasks_for_files(
                    session, unreachable_file_ids
                )
                mark_document_modified(document, user.username)
                delete_revision_and_unreferenced_file(session, revision)
            session.commit()

        publish_cancelled_file_tasks(cancelled_task_ids)

        handler.conclude_request(200, {}, "Revision deleted successfully")
        return Result(code=200, target=revision_id, username=handler.username)

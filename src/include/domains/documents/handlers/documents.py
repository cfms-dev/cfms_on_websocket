__all__ = [
    "RequestCreateDocumentHandler",
    "RequestDeleteDocumentHandler",
    "RequestDownloadFileHandler",
    "RequestGetDocumentDaclHandler",
    "RequestGetDocumentHandler",
    "RequestGetDocumentInfoHandler",
    "RequestPurgeDocumentHandler",
    "RequestRenameDocumentHandler",
    "RequestReparentDocumentHandler",
    "RequestRestoreDocumentHandler",
    "RequestSetDocumentDaclHandler",
    "RequestSetDocumentTagsHandler",
    "RequestUploadDocumentHandler",
    "RequestUploadFileHandler",
]

import datetime
import secrets
import time
import uuid
from typing import Annotated, Any

from cacl_compiler import AtomicOp, ObjectType
from pydantic import ConfigDict, Field, StringConstraints
lazy from sqlalchemy.orm import Session as ORMSession

from include.config.constants import (
    DACL_SOURCE_MAX_LENGTH,
    DOWNLOAD_TRANSFER_MAX_CHUNK_SIZE,
    DOWNLOAD_TRANSFER_MIN_CHUNK_SIZE,
    FILE_TASK_DEFAULT_DURATION_SECONDS,
    ROOT_DIRECTORY_ID,
    UPLOAD_TRANSFER_MIN_CHUNK_SIZE,
)
from include.config.validation import DocumentUploadPolicy
from include.database.clock import database_now
from include.database.models.documents import (
    Document,
    DocumentMetadata,
    DocumentMetadataTag,
    DocumentRevision,
    EntityStatus,
    Folder,
)
from include.database.models.files import File, FileTask, FileTaskStatus, TransferMode
from include.database.models.identity import User
from include.database.session import Session
from include.domains.access.authorization.evaluation import (
    authorize_create_on_parent,
    authorize_dacl_read,
    authorize_node_operation,
    authorize_reparent,
    authorize_restore,
    authorize_write_dacl_and_load_path,
    simulate_dacl_save_lockout,
    would_self_lockout_on_create,
)
from include.domains.access.authorization.storage import (
    compile_policy_source,
    delete_node_dacl_rules_for_targets,
    persist_node_policy,
    render_policy_text,
)
from include.domains.access.permissions import Permissions
from include.domains.documents.commands.file_tasks import (
    cancel_file_tasks_for_files,
    expire_file_task_if_due,
    serialize_file_task,
)
from include.domains.documents.commands.name_conflicts import (
    NodeNameConflictError,
    describe_node_name_conflict,
    node_name_mutation,
)
from include.domains.documents.commands.revision_deletion import (
    delete_all_document_revisions,
)
from include.domains.documents.commands.upload_cleanup import (
    try_reclaim_abandoned_uploads,
)
from include.domains.documents.creation_limits import check_document_creation_limits
from include.domains.documents.download_limits import check_download_issue_limits
from include.domains.documents.file_task_signals import publish_cancelled_file_tasks
from include.domains.documents.handlers.name_conflict_responses import (
    respond_to_node_name_conflict,
)
from include.domains.documents.queries.file_references import (
    find_unreachable_document_file_ids,
)
from include.domains.documents.queries.listing import (
    fetch_latest_active_revisions_by_document,
)
from include.domains.security.guards.rate_limits import risk_control_transaction
from include.exceptions.misc import NoActiveRevisionsError
from include.messages import Messages as smsg
from include.transport.request_handler import (
    REQUEST_UNSET,
    Omittable,
    RequestDataModel,
    RequestHandler,
    Result,
)
from include.types import JsonInteger, NonEmptyString
lazy from include.domains.documents.types import RevisionID

_Sha256 = Annotated[str, StringConstraints(pattern="^[0-9A-Fa-f]{64}$")]
_Tag = Annotated[str, StringConstraints(min_length=1, max_length=255)]
_NonNegativeInteger = Annotated[JsonInteger, Field(ge=0)]
_DaclSource = Annotated[str, StringConstraints(max_length=DACL_SOURCE_MAX_LENGTH)]


class _DocumentInfoRequest(RequestDataModel):
    model_config = ConfigDict(
        strict=True,
        validate_default=True,
        extra="allow",
    )

    document_id: NonEmptyString


class _DocumentIDRequest(RequestDataModel):
    document_id: NonEmptyString


class _GetDocumentDaclRequest(RequestDataModel):
    document_id: NonEmptyString
    annotate_users: Omittable[bool] = REQUEST_UNSET


class _SetDocumentDaclRequest(RequestDataModel):
    document_id: NonEmptyString
    dacl: _DaclSource
    allow_self_lockout: Omittable[bool] = REQUEST_UNSET


class _CreateDocumentRequest(RequestDataModel):
    folder_id: str | None = None
    title: NonEmptyString
    dacl: Omittable[_DaclSource] = REQUEST_UNSET
    allow_self_lockout: Omittable[bool] = REQUEST_UNSET


class _UploadDocumentRequest(RequestDataModel):
    document_id: NonEmptyString
    parent_revision_id: RevisionID | None = None


class _RenameDocumentRequest(RequestDataModel):
    document_id: NonEmptyString
    new_title: NonEmptyString


class _DownloadFileRequest(RequestDataModel):
    task_id: NonEmptyString
    offset: Omittable[_NonNegativeInteger] = REQUEST_UNSET
    max_chunk_size: Annotated[
        JsonInteger,
        Field(
            ge=DOWNLOAD_TRANSFER_MIN_CHUNK_SIZE,
            le=DOWNLOAD_TRANSFER_MAX_CHUNK_SIZE,
        ),
    ]


class _UploadFileRequest(RequestDataModel):
    task_id: NonEmptyString
    file_size: _NonNegativeInteger
    sha256: _Sha256 | None
    max_chunk_size: Annotated[JsonInteger, Field(ge=UPLOAD_TRANSFER_MIN_CHUNK_SIZE)]
    restart: Omittable[bool] = REQUEST_UNSET


class _ReparentDocumentRequest(RequestDataModel):
    document_id: NonEmptyString
    target_folder_id: str | None = None


class _RestoreDocumentRequest(RequestDataModel):
    document_id: NonEmptyString
    target_folder_id: str | None = None
    new_title: Omittable[NonEmptyString] = REQUEST_UNSET


class _SetDocumentTagsRequest(RequestDataModel):
    document_id: NonEmptyString
    tags: Annotated[list[_Tag], Field(max_length=128)]


def create_file_task(
    session: ORMSession,
    file: File,
    transfer_mode: TransferMode = TransferMode.DOWNLOAD,
    *,
    issued_by_id: uuid.UUID | None = None,
) -> dict[str, Any]:
    if not file:
        raise ValueError("File can not be None when creating a file task")

    now = database_now(session)
    duration = (
        DocumentUploadPolicy.from_options(session).start_timeout_seconds
        if transfer_mode == TransferMode.UPLOAD
        else FILE_TASK_DEFAULT_DURATION_SECONDS
    )
    task = FileTask(
        file_id=file.id,
        status=FileTaskStatus.PENDING,
        mode=transfer_mode,
        start_time=now,
        end_time=now + duration,
        issued_by_id=issued_by_id,
    )
    session.add(task)
    session.flush()

    return serialize_file_task(task)


def get_or_create_document_metadata(document: Document) -> DocumentMetadata:
    if document.metadata_record is None:
        document.metadata_record = DocumentMetadata()
    return document.metadata_record


def mark_document_modified(document: Document, user_id: uuid.UUID) -> None:
    get_or_create_document_metadata(document).last_modified_by_id = user_id


def serialize_document_metadata(document: Document) -> dict:
    metadata = document.metadata_record
    if metadata is None:
        return {
            "tags": [],
            "creator": None,
            "last_modified_by": None,
        }

    return {
        "tags": [tag.tag for tag in metadata.tags],
        "creator": str(metadata.creator_id) if metadata.creator_id else None,
        "last_modified_by": str(metadata.last_modified_by_id)
        if metadata.last_modified_by_id
        else None,
    }


class RequestGetDocumentInfoHandler(RequestHandler[_DocumentInfoRequest]):
    """Handles the "core.document.info.get" action."""

    request_model = _DocumentInfoRequest

    requires_auth = True
    rate_limit_cost = 3

    def handle(self, handler, request):
        document_id = request.document_id

        if not document_id:
            handler.conclude_request(400, {}, smsg.DOCUMENT_ID_REQUIRED)
            return

        with Session() as session:
            user = User.get_existing(session, handler.user_id)
            document = session.get(Document, document_id)

            if not document:
                handler.conclude_request(404, {}, smsg.DOCUMENT_NOT_FOUND)
                return Result(code=404, target=document_id, user_id=handler.user_id)

            latest_revision = fetch_latest_active_revisions_by_document(
                session, [document.id]
            ).get(document.id)
            if latest_revision is None:
                handler.conclude_request(
                    404, {}, "No active revisions found for this document"
                )
                return Result(code=404, target=document_id, user_id=handler.user_id)

            if not authorize_node_operation(
                session, user, document, AtomicOp.READ_METADATA
            ).allowed:
                handler.conclude_access_denial()
                return Result(code=403, target=document_id, user_id=handler.user_id)

            data = {
                "document_id": document.id,
                "parent_id": document.folder_id,
                "title": document.title,
                "size": latest_revision.file.size,
                "created_time": document.created_time,
                "last_modified": latest_revision.created_time,
                "metadata": serialize_document_metadata(document),
            }

            handler.conclude_request(200, data, "Document info retrieved successfully")
            return Result(code=0, target=document_id, user_id=handler.user_id)


class RequestGetDocumentDaclHandler(RequestHandler[_GetDocumentDaclRequest]):
    """Handles the "core.document.dacl.get" action."""

    request_model = _GetDocumentDaclRequest
    requires_auth = True
    rate_limit_cost = 2

    def handle(self, handler, request):
        document_id: str = request.document_id
        annotate_users: bool = (
            request.annotate_users
            if request.annotate_users is not REQUEST_UNSET
            else False
        )

        with Session() as session:
            user = User.get_existing(session, handler.user_id)
            document = session.get(Document, document_id)

            if not document:
                handler.conclude_request(404, {}, smsg.DOCUMENT_NOT_FOUND)
                return Result(code=404, target=document_id, user_id=handler.user_id)

            allowed, policy = authorize_dacl_read(session, user, document)
            if not allowed or policy is None:
                handler.conclude_request(403, {}, smsg.ACCESS_DENIED_READ_DACL)
                return Result(code=403, target=document_id, user_id=handler.user_id)

            response_data: dict[str, Any] = {
                "dacl": render_policy_text(policy),
                "inherit": policy.inherit,
                "fingerprint": policy.fingerprint(),
            }
            if annotate_users:
                response_data["annotated_dacl"] = render_policy_text(
                    policy, session=session, annotate_users=True
                )

            handler.conclude_request(
                200,
                response_data,
                "Document DACL retrieved successfully",
            )
            return Result(code=0, target=document_id, user_id=handler.user_id)


class RequestSetDocumentDaclHandler(RequestHandler[_SetDocumentDaclRequest]):
    """Handles the "core.document.dacl.set" action."""

    request_model = _SetDocumentDaclRequest
    requires_auth = True
    rate_limit_cost = 5

    def handle(self, handler, request):
        document_id: str = request.document_id
        dacl_source: str = request.dacl
        allow_self_lockout: bool = (
            request.allow_self_lockout
            if request.allow_self_lockout is not REQUEST_UNSET
            else False
        )

        with Session() as session:
            user = User.get_existing(session, handler.user_id)
            document = session.get(Document, document_id)

            if not document:
                handler.conclude_request(404, {}, smsg.DOCUMENT_NOT_FOUND)
                return Result(code=404, target=document_id, user_id=handler.user_id)

            authorized, current_path, check_traverse = (
                authorize_write_dacl_and_load_path(session, user, document)
            )
            if not authorized:
                handler.conclude_request(403, {}, smsg.ACCESS_DENIED_WRITE_DACL)
                return Result(code=403, target=document_id, user_id=handler.user_id)

            compiled = compile_policy_source(
                session,
                dacl_source,
                target_type=ObjectType.DOCUMENT,
                strict_principals=False,
            )
            serialized_diags = [d.to_dict() for d in compiled.diagnostics]
            if not compiled.ok or compiled.policy is None:
                handler.conclude_request(
                    400,
                    {"diagnostics": serialized_diags},
                    "Invalid CACL policy",
                )
                return Result(code=400, target=document_id, user_id=handler.user_id)

            self_lockout_warning = simulate_dacl_save_lockout(
                user,
                current_path,
                compiled.policy,
                check_ancestor_traverse=check_traverse,
            )
            if self_lockout_warning and not allow_self_lockout:
                handler.conclude_request(
                    409,
                    {
                        "self_lockout_warning": True,
                        "diagnostics": serialized_diags,
                    },
                    smsg.DACL_SELF_LOCKOUT,
                )
                return Result(code=409, target=document_id, user_id=handler.user_id)

            persist_node_policy(session, document, compiled.policy)
            mark_document_modified(document, user.id)
            session.commit()

            handler.conclude_request(
                200,
                {
                    "dacl": render_policy_text(compiled.policy),
                    "inherit": compiled.policy.inherit,
                    "fingerprint": compiled.policy.fingerprint(),
                    "diagnostics": serialized_diags,
                    "self_lockout_warning": self_lockout_warning,
                },
                "Document DACL updated successfully",
            )
            return Result(code=0, target=document_id, user_id=handler.user_id)


class RequestGetDocumentHandler(RequestHandler[_DocumentIDRequest]):
    """Handles the "core.document.get" action."""

    request_model = _DocumentIDRequest

    requires_auth = True
    rate_limit_cost = 3

    def handle(self, handler, request):
        document_id: str = request.document_id

        with Session() as session, risk_control_transaction(session):
            user = User.get_existing(session, handler.user_id)
            document = session.get(Document, document_id)

            if not document:
                response_code = result_code = 404
                data = {}
                message = smsg.DOCUMENT_NOT_FOUND
            elif not authorize_node_operation(
                session, user, document, AtomicOp.READ_CONTENT
            ).allowed:
                response_code = result_code = 403
                data = {}
                message = smsg.ACCESS_DENIED
            else:
                latest_revision = fetch_latest_active_revisions_by_document(
                    session, [document.id]
                ).get(document.id)
                if latest_revision is None:
                    response_code = 404
                    result_code = 4041
                    data = {}
                    message = "No active revisions found for this document"
                else:
                    limit_decision = check_download_issue_limits(
                        session,
                        user.id,
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
                            "retry_after_seconds": (limit_decision.retry_after_seconds),
                        }
                        message = (
                            "Download request limit exceeded. Please try again later."
                        )
                    else:
                        task_data = create_file_task(
                            session,
                            latest_revision.file,
                            issued_by_id=user.id,
                        )
                        response_code = 200
                        result_code = 0
                        data = {
                            "document_id": document.id,
                            "title": document.title,
                            "task_data": task_data,
                        }
                        message = "Document successfully fetched"

        handler.conclude_request(response_code, data, message)
        return Result(
            code=result_code,
            target=document_id,
            data=data if result_code == 429 else None,
            user_id=handler.user_id,
        )


def _create_document_in_transaction(
    session: ORMSession,
    user_id: uuid.UUID,
    remote_address: str,
    folder_id: str,
    title: str,
    dacl_source: str | None,
    allow_self_lockout: bool,
) -> tuple[int, dict[str, Any], str, Result]:
    result_data = {"title": title}

    with risk_control_transaction(session):
        user = User.get_existing(session, user_id)

        parent_folder = session.get(Folder, folder_id or ROOT_DIRECTORY_ID)
        if parent_folder is None:
            return (
                404,
                {},
                smsg.TARGET_DIRECTORY_NOT_FOUND,
                Result(
                    code=404,
                    target=folder_id,
                    data=result_data,
                    user_id=user_id,
                ),
            )

        can_create, can_write_dacl, parent_path, check_traverse = (
            authorize_create_on_parent(
                session,
                user,
                parent_folder,
                AtomicOp.CREATE_DOCUMENT,
                require_write_dacl=dacl_source is not None,
            )
        )
        if not can_create:
            return (
                403,
                {},
                smsg.ACCESS_DENIED_WRITE_DIRECTORY,
                Result(
                    code=403,
                    target=folder_id,
                    data=result_data,
                    user_id=user_id,
                ),
            )

        compiled_policy = None
        if dacl_source is not None:
            if not can_write_dacl:
                return (
                    403,
                    {},
                    smsg.ACCESS_DENIED_WRITE_DACL,
                    Result(
                        code=403,
                        target=folder_id,
                        data=result_data,
                        user_id=user_id,
                    ),
                )
            compiled = compile_policy_source(
                session,
                dacl_source,
                target_type=ObjectType.DOCUMENT,
                strict_principals=False,
            )
            serialized_diags = [d.to_dict() for d in compiled.diagnostics]
            if not compiled.ok or compiled.policy is None:
                return (
                    400,
                    {"diagnostics": serialized_diags},
                    "Invalid CACL policy",
                    Result(
                        code=400,
                        target=folder_id,
                        data=result_data,
                        user_id=user_id,
                    ),
                )
            compiled_policy = compiled.policy

            if not allow_self_lockout and would_self_lockout_on_create(
                session,
                user,
                parent_folder,
                ObjectType.DOCUMENT,
                title,
                compiled_policy,
                parent_path=parent_path,
                check_ancestor_traverse=check_traverse,
            ):
                return (
                    409,
                    {
                        "self_lockout_warning": True,
                        "diagnostics": serialized_diags,
                    },
                    smsg.DACL_SELF_LOCKOUT,
                    Result(
                        code=409,
                        target=folder_id,
                        data=result_data,
                        user_id=user_id,
                    ),
                )

        limit_decision = check_document_creation_limits(
            session,
            user.id,
            remote_address,
            account_created_at=user.created_time,
            bypass_rate_limit=(
                Permissions.BYPASS_DOCUMENT_CREATION_RATE_LIMIT in user.all_permissions
            ),
        )
        if not limit_decision.allowed:
            response_data = {
                "scope": limit_decision.scope,
                "limit": limit_decision.limit,
                "retry_after_seconds": limit_decision.retry_after_seconds,
            }
            return (
                429,
                response_data,
                "Document creation limit exceeded. Please try again later.",
                Result(
                    code=429,
                    target=folder_id,
                    data={**result_data, **response_data},
                    user_id=user_id,
                ),
            )

        today = datetime.datetime.now(datetime.UTC).date()
        new_file = File(
            id=secrets.token_hex(32),
            path=(f"content/files/{today.year}/{today.month}/{secrets.token_hex(32)}"),
        )
        new_document = Document(
            id=secrets.token_hex(32),
            title=title,
            folder_id=folder_id,
        )
        new_document.metadata_record = DocumentMetadata(
            creator_id=user.id,
            last_modified_by_id=user.id,
        )
        new_revision = DocumentRevision(file_id=new_file.id)
        new_document.revisions.append(new_revision)
        session.add_all((new_file, new_document, new_revision))

        with node_name_mutation(session, folder_id, title):
            session.flush()
            if compiled_policy is not None:
                persist_node_policy(session, new_document, compiled_policy)
            new_document.current_revision = new_revision
            task_data = create_file_task(
                session,
                new_file,
                transfer_mode=TransferMode.UPLOAD,
            )
            return (
                200,
                {
                    "document_id": new_document.id,
                    "task_data": task_data,
                },
                "Task successfully created",
                Result(
                    code=0,
                    target=folder_id,
                    data=result_data,
                    user_id=user_id,
                ),
            )


class RequestCreateDocumentHandler(RequestHandler[_CreateDocumentRequest]):
    """Handles the "core.document.create" action."""

    request_model = _CreateDocumentRequest

    requires_auth = True
    rate_limit_cost = 5

    def handle(self, handler, request):
        folder_id = request.folder_id or ROOT_DIRECTORY_ID
        title = (request.title or "").strip()
        dacl_source = request.dacl if request.dacl is not REQUEST_UNSET else None
        allow_self_lockout = (
            request.allow_self_lockout
            if request.allow_self_lockout is not REQUEST_UNSET
            else False
        )

        if not title:
            handler.conclude_request(400, {}, smsg.DOCUMENT_TITLE_REQUIRED)
            return

        try_reclaim_abandoned_uploads(folder_id=folder_id, title=title)

        outcome: tuple[int, dict[str, Any], str, Result] | None = None
        conflict_response: tuple[dict[str, Any], str] | None = None

        assert handler.token, "Authenticated requests must have a valid token"
        with Session() as session:
            try:
                outcome = _create_document_in_transaction(
                    session,
                    handler.token.sub,
                    handler.remote_address,
                    folder_id,
                    title,
                    dacl_source,
                    allow_self_lockout,
                )
            except NodeNameConflictError:
                user = User.get_existing(session, handler.user_id)
                conflict_response = describe_node_name_conflict(
                    session, user, folder_id, title
                )

        if conflict_response is not None:
            payload, message = conflict_response
            return respond_to_node_name_conflict(
                handler,
                payload,
                message,
                target=folder_id,
                result_data={"title": title},
            )

        assert outcome is not None, "Document creation must produce an outcome"
        response_code, response_data, message, result = outcome
        handler.conclude_request(response_code, response_data, message)
        return result


class RequestUploadDocumentHandler(RequestHandler[_UploadDocumentRequest]):
    """Handles the "core.document.upload" action."""

    request_model = _UploadDocumentRequest

    requires_auth = True
    rate_limit_cost = 5

    def handle(self, handler, request):
        document_id = request.document_id

        try_reclaim_abandoned_uploads(document_id=document_id)

        with Session() as session:
            document = session.get(Document, document_id)
            this_user = User.get_existing(session, handler.user_id)

            if document:
                if not authorize_node_operation(
                    session, this_user, document, AtomicOp.WRITE_CONTENT
                ).allowed:
                    handler.conclude_access_denial()
                    return Result(code=403, target=document_id, user_id=handler.user_id)

                existing_task = (
                    session.query(FileTask)
                    .join(File, File.id == FileTask.file_id)
                    .join(DocumentRevision, DocumentRevision.file_id == File.id)
                    .filter(
                        DocumentRevision.document_id == document_id,
                        FileTask.mode == TransferMode.UPLOAD,
                        FileTask.status.in_(
                            (
                                FileTaskStatus.PENDING,
                                FileTaskStatus.IN_PROGRESS,
                            )
                        ),
                    )
                    .order_by(FileTask.start_time.desc())
                    .first()
                )
                if existing_task is not None:
                    status = expire_file_task_if_due(session, existing_task.id)
                    if status == FileTaskStatus.EXPIRED:
                        session.commit()
                        handler.conclude_request(
                            410,
                            {"task_status": "expired"},
                            "Existing upload task has expired",
                        )
                        return Result(
                            code=410, target=document_id, user_id=handler.user_id
                        )
                    if status == FileTaskStatus.IN_PROGRESS:
                        handler.conclude_request(
                            409,
                            {"task_status": "in_progress"},
                            "Upload is already in progress",
                        )
                        return Result(
                            code=409, target=document_id, user_id=handler.user_id
                        )

                    task_data = serialize_file_task(existing_task)
                    handler.conclude_request(
                        200,
                        {"task_data": task_data},
                        "Existing upload task returned",
                    )
                    return Result(
                        code=0,
                        target=document_id,
                        data=task_data,
                        user_id=handler.user_id,
                    )

                today = datetime.datetime.now(datetime.UTC).date()

                file_id = secrets.token_hex(32)
                real_filename = secrets.token_hex(32)

                new_file = File(
                    id=file_id,
                    path=f"content/files/{today.year}/{today.month}/{real_filename}",
                )

                if "parent_revision_id" in request.model_fields_set:
                    parent_revision_id = request.parent_revision_id

                    if parent_revision_id and parent_revision_id not in [
                        rev.id for rev in document.revisions
                    ]:
                        handler.conclude_request(
                            400,
                            {},
                            "Parent revision does not exist or does not belong to this document",
                        )
                        return Result(
                            code=400, target=document_id, user_id=handler.user_id
                        )
                else:
                    try:
                        parent_revision_id = document.get_latest_revision().id
                    except NoActiveRevisionsError:
                        parent_revision_id = None

                new_revision = DocumentRevision(
                    document_id=document_id,
                    file_id=file_id,
                    parent_revision_id=parent_revision_id,
                )
                session.add(new_file)
                session.add(new_revision)

                document.revisions.append(new_revision)
                mark_document_modified(document, this_user.id)

                document.current_revision = new_revision
                task_data = create_file_task(session, new_file, TransferMode.UPLOAD)
                session.commit()

            else:
                handler.conclude_request(404, {}, smsg.DOCUMENT_NOT_FOUND)
                return Result(code=404, target=document_id, user_id=handler.user_id)

        handler.conclude_request(
            200, {"task_data": task_data}, "Task successfully created"
        )
        return Result(
            code=0, target=document_id, data=task_data, user_id=handler.user_id
        )


class RequestDeleteDocumentHandler(RequestHandler[_DocumentIDRequest]):
    """Handles the "core.document.delete" action."""

    request_model = _DocumentIDRequest

    requires_auth = True
    rate_limit_cost = 5

    def handle(self, handler, request):
        document_id = request.document_id
        cancelled_task_ids: list[str] = []

        with Session() as session:
            user = User.get_existing(session, handler.user_id)
            document = session.get(Document, document_id)

            if not document:
                handler.conclude_request(404, {}, smsg.DOCUMENT_NOT_FOUND)
                return Result(code=404, target=document_id, user_id=handler.user_id)

            if not authorize_node_operation(
                session, user, document, AtomicOp.DELETE
            ).allowed:
                handler.conclude_access_denial()
                return Result(code=403, target=document_id, user_id=handler.user_id)

            document.status = EntityStatus.DELETED
            document.status_operation_id = (
                f"OP_DEL_{secrets.token_hex(8)}_{int(time.time())}"
            )
            unreachable_file_ids = find_unreachable_document_file_ids(
                session, [document_id]
            )
            cancelled_task_ids = cancel_file_tasks_for_files(
                session, unreachable_file_ids
            )
            mark_document_modified(document, user.id)
            session.commit()

        publish_cancelled_file_tasks(cancelled_task_ids)

        handler.conclude_request(200, {}, "Document successfully deleted")
        return Result(code=0, target=document_id, user_id=handler.user_id)


class RequestRenameDocumentHandler(RequestHandler[_RenameDocumentRequest]):
    """Handles the "core.document.rename" action."""

    request_model = _RenameDocumentRequest

    requires_auth = True
    rate_limit_cost = 3

    def handle(self, handler, request):
        document_id: str = request.document_id
        new_title: str = request.new_title

        with Session() as session:
            this_user = User.get_existing(session, handler.user_id)
            document = session.get(Document, document_id)

            if not document:
                handler.conclude_request(404, {}, smsg.DOCUMENT_NOT_FOUND)
                return Result(code=404, target=document_id, user_id=handler.user_id)

            if not authorize_node_operation(
                session, this_user, document, AtomicOp.RENAME
            ).allowed:
                handler.conclude_access_denial()
                return Result(code=403, target=document_id, user_id=handler.user_id)

            if document.title == new_title:
                handler.conclude_request(
                    code=400,
                    message="New name is the same as the current name",
                    data={},
                )
                return

            parent_id = document.folder_id or ROOT_DIRECTORY_ID
            old_title = document.title
            try:
                with node_name_mutation(session, parent_id, new_title):
                    document.title = new_title
                    mark_document_modified(document, this_user.id)
                    session.commit()
            except NodeNameConflictError:
                payload, message = describe_node_name_conflict(
                    session, this_user, parent_id, new_title
                )
                return respond_to_node_name_conflict(
                    handler,
                    payload,
                    message,
                    target=parent_id,
                    result_data={"title": old_title},
                )

            handler.conclude_request(
                code=200, message="Document renamed successfully", data={}
            )
            return Result(code=0, target=document_id, user_id=handler.user_id)


class RequestDownloadFileHandler(RequestHandler[_DownloadFileRequest]):
    """Handles the "core.file.download" action."""

    request_model = _DownloadFileRequest
    rate_limit_cost = 5

    def handle(self, handler, request):
        task_id: str = request.task_id
        offset: int = request.offset if request.offset is not REQUEST_UNSET else 0
        max_chunk_size: int = request.max_chunk_size

        handler.send_file(task_id, offset, max_chunk_size)


class RequestUploadFileHandler(RequestHandler[_UploadFileRequest]):
    """Handles the "core.file.upload" action."""

    request_model = _UploadFileRequest
    rate_limit_cost = 5

    def handle(self, handler, request):
        task_id = request.task_id
        file_size = request.file_size
        sha256 = request.sha256
        max_chunk_size = request.max_chunk_size
        restart = request.restart if request.restart is not REQUEST_UNSET else False

        handler.receive_file(
            task_id,
            file_size,
            sha256.lower() if sha256 is not None else None,
            max_chunk_size,
            restart,
        )


class RequestReparentDocumentHandler(RequestHandler[_ReparentDocumentRequest]):
    """Handles the "core.document.reparent" action."""

    request_model = _ReparentDocumentRequest

    requires_auth = True
    rate_limit_cost = 3

    def handle(self, handler, request):
        document_id: str = request.document_id
        target_folder_id: str = request.target_folder_id or ROOT_DIRECTORY_ID

        with Session() as session:
            user = User.get_existing(session, handler.user_id)
            document = session.get(Document, document_id)
            if not document:
                handler.conclude_request(
                    code=404, message=smsg.TARGET_DOCUMENT_NOT_FOUND, data={}
                )
                return Result(
                    code=404,
                    target=document_id,
                    data={"target_folder_id": target_folder_id},
                    user_id=handler.user_id,
                )

            if (document.folder_id or ROOT_DIRECTORY_ID) == target_folder_id:
                handler.conclude_request(400, {}, smsg.CANNOT_REPARENT_TO_SAME_FOLDER)
                return Result(
                    code=400,
                    target=document_id,
                    data={"target_folder_id": target_folder_id},
                    user_id=handler.user_id,
                )

            target_folder = session.get(Folder, target_folder_id)
            if not target_folder:
                handler.conclude_request(
                    code=404, message=smsg.TARGET_DIRECTORY_NOT_FOUND, data={}
                )
                return Result(
                    code=404,
                    target=document_id,
                    data={"target_folder_id": target_folder_id},
                    user_id=handler.user_id,
                )

            if not authorize_reparent(session, user, document, target_folder).allowed:
                handler.conclude_request(403, {}, smsg.ACCESS_DENIED_REPARENT_DOCUMENT)
                return Result(
                    code=403,
                    target=document_id,
                    data={"target_folder_id": target_folder_id},
                    user_id=handler.user_id,
                )

            source_folder_id = document.folder_id or ROOT_DIRECTORY_ID
            title = document.title
            try:
                with node_name_mutation(session, target_folder_id, title):
                    document.folder = target_folder
                    mark_document_modified(document, user.id)
                    session.commit()
            except NodeNameConflictError:
                payload, message = describe_node_name_conflict(
                    session, user, target_folder_id, title
                )
                return respond_to_node_name_conflict(
                    handler,
                    payload,
                    message,
                    target=source_folder_id,
                    result_data={"title": title},
                )

        handler.conclude_request(200, {}, smsg.SUCCESS)
        return Result(
            code=0,
            target=document_id,
            data={"target_folder_id": target_folder_id},
            user_id=handler.user_id,
        )


class RequestPurgeDocumentHandler(RequestHandler[_DocumentIDRequest]):
    """Handles the "core.document.purge" action."""

    request_model = _DocumentIDRequest

    requires_auth = True
    rate_limit_cost = 10

    def handle(self, handler, request):
        doc_id = request.document_id
        with Session() as session:
            user = User.get_existing(session, handler.user_id)

            if Permissions.PURGE not in user.all_permissions:
                handler.conclude_permission_denial()
                return

            document = session.get(
                Document, doc_id, execution_options={"include_deleted": True}
            )
            if document is None:
                handler.conclude_request(404, {}, smsg.DOCUMENT_NOT_FOUND)
                return

            if document.status != EntityStatus.DELETED:
                handler.conclude_request(
                    400, {}, "Document must be marked as deleted before purging"
                )
                return

            if not authorize_node_operation(
                session, user, document, AtomicOp.PURGE, include_deleted=True
            ).allowed:
                handler.conclude_access_denial()
                return

            delete_node_dacl_rules_for_targets(session, [doc_id])
            delete_all_document_revisions(session, document)
            mark_document_modified(document, user.id)
            session.delete(document)
            session.commit()

        handler.conclude_request(200, {}, "Document permanently deleted")
        return Result(code=0, target=doc_id, user_id=handler.user_id)


class RequestRestoreDocumentHandler(RequestHandler[_RestoreDocumentRequest]):
    """Handles the "core.document.restore" action."""

    request_model = _RestoreDocumentRequest

    requires_auth = True
    rate_limit_cost = 3

    def handle(self, handler, request):
        doc_id = request.document_id

        target_folder_provided = "target_folder_id" in request.model_fields_set
        target_folder_id: str | None = request.target_folder_id
        new_title = (
            request.new_title if request.new_title is not REQUEST_UNSET else None
        )

        with Session() as session:
            user = User.get_existing(session, handler.user_id)

            document = session.get(
                Document, doc_id, execution_options={"include_deleted": True}
            )
            if not document or document.status != EntityStatus.DELETED:
                handler.conclude_request(404, {}, smsg.DELETED_DOCUMENT_NOT_FOUND)
                return Result(code=404, target=doc_id, user_id=handler.user_id)

            if target_folder_provided:
                db_folder_id = target_folder_id or ROOT_DIRECTORY_ID
            else:
                db_folder_id = document.folder_id or ROOT_DIRECTORY_ID

            final_title = new_title if new_title else document.title

            target_folder = session.get(
                Folder, db_folder_id, execution_options={"include_deleted": True}
            )
            if not target_folder:
                handler.conclude_request(404, {}, smsg.TARGET_DIRECTORY_NOT_FOUND)
                return Result(code=404, target=db_folder_id, user_id=handler.user_id)

            if target_folder.status != EntityStatus.OK:
                handler.conclude_request(
                    409,
                    {"folder_id": db_folder_id},
                    "Cannot restore: Target folder is deleted. Restore it first.",
                )
                return Result(code=409, target=doc_id, user_id=handler.user_id)

            if not authorize_restore(session, user, document, target_folder).allowed:
                handler.conclude_access_denial()
                return Result(code=403, target=doc_id, user_id=handler.user_id)

            try:
                with node_name_mutation(session, db_folder_id, final_title):
                    document.status = EntityStatus.OK
                    document.status_operation_id = None
                    document.title = final_title
                    document.folder_id = db_folder_id
                    mark_document_modified(document, user.id)
                    session.commit()
            except NodeNameConflictError:
                payload, message = describe_node_name_conflict(
                    session, user, db_folder_id, final_title
                )
                return respond_to_node_name_conflict(
                    handler,
                    payload,
                    message,
                    target=doc_id,
                    result_data={},
                )

            handler.conclude_request(
                200,
                {
                    "title": final_title,
                    "folder_id": db_folder_id,
                },
                "Document successfully restored",
            )
            return Result(code=0, target=doc_id, user_id=handler.user_id)


class RequestSetDocumentTagsHandler(RequestHandler[_SetDocumentTagsRequest]):
    request_model = _SetDocumentTagsRequest

    requires_auth = True
    rate_limit_cost = 3

    def handle(self, handler, request):
        document_id: str = request.document_id

        normalized_tags = []
        seen_tags = set()
        for raw_tag in request.tags:
            tag = raw_tag.strip()
            if not tag:
                handler.conclude_request(400, {}, "Tags cannot be blank")
                return Result(code=400, target=document_id, user_id=handler.user_id)
            if tag not in seen_tags:
                normalized_tags.append(tag)
                seen_tags.add(tag)

        with Session() as session:
            user = User.get_existing(session, handler.user_id)
            document = session.get(Document, document_id)

            if not document:
                handler.conclude_request(404, {}, smsg.DOCUMENT_NOT_FOUND)
                return Result(code=404, target=document_id, user_id=handler.user_id)

            if not authorize_node_operation(
                session, user, document, AtomicOp.WRITE_METADATA
            ).allowed:
                handler.conclude_access_denial()
                return Result(code=403, target=document_id, user_id=handler.user_id)

            metadata = get_or_create_document_metadata(document)
            existing_by_tag = {
                tag_record.tag: tag_record for tag_record in metadata.tags
            }
            requested_tag_set = set(normalized_tags)

            for tag_record in list(metadata.tags):
                if tag_record.tag not in requested_tag_set:
                    metadata.tags.remove(tag_record)

            for position, tag in enumerate(normalized_tags):
                if tag in existing_by_tag:
                    existing_by_tag[tag].position = position
                else:
                    metadata.tags.append(
                        DocumentMetadataTag(tag=tag, position=position)
                    )

            metadata.last_modified_by_id = user.id
            session.commit()

            handler.conclude_request(
                200,
                {"tags": normalized_tags},
                "Document metadata tags updated successfully",
            )
            return Result(
                code=0,
                target=document_id,
                data={"tags": normalized_tags},
                user_id=handler.user_id,
            )

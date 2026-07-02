__all__ = [
    "RequestGetDocumentInfoHandler",
    "RequestGetDocumentHandler",
    "RequestCreateDocumentHandler",
    "RequestUploadDocumentHandler",
    "RequestDeleteDocumentHandler",
    "RequestRenameDocumentHandler",
    "RequestDownloadFileHandler",
    "RequestUploadFileHandler",
    "RequestSetDocumentRulesHandler",
    "RequestSetDocumentTagsHandler",
    "RequestMoveDocumentHandler",
]

import datetime
import secrets
import time
from typing import Any

import jsonschema

from include.config.constants import (
    FILE_TASK_DEFAULT_DURATION_SECONDS,
    ROOT_DIRECTORY_ID,
)
from include.database.models.documents import (
    Document,
    DocumentMetadata,
    DocumentMetadataTag,
    DocumentRevision,
    EntityStatus,
    Folder,
)
from include.database.models.files import File, FileTask, TransferMode
from include.database.models.identity import User
from include.database.session import Session
from include.domains.access.authorization.access_rules import apply_access_rules
from include.domains.access.authorization.compiled_rules import (
    get_access_rules_json,
    get_access_rules_list,
)
from include.domains.access.permissions import Permissions
from include.domains.documents.commands.name_conflicts import (
    get_target_folder_and_check_write,
    handle_name_duplicate,
)
from include.exceptions.misc import NoActiveRevisionsError
from include.messages import Messages as smsg
from include.transport.connection import ConnectionHandler
from include.transport.request_handler import RequestHandler, Result


def create_file_task(
    file: File, transfer_mode: TransferMode = TransferMode.DOWNLOAD
) -> dict[str, Any]:
    """
    Creates a new file processing task for the specified file.
    Args:
        file (File): The file object for which the task is to be generated.
    Returns:
        dict or None: A dictionary containing the task details:
            - task_id (int): The unique identifier of the created task.
            - provider (str): The file transfer provider (e.g., "native").
            - start_time (float): The start time of the task.
            - end_time (float): The end time of the task (1 hour after start).
        Returns None if the file with the given file_id does not exist.
    """

    with Session() as session:
        if not file:
            raise ValueError("File can not be None when creating a file task")

        now = time.time()
        task = FileTask(
            file_id=file.id,
            status=0,
            mode=transfer_mode,
            start_time=now,
            end_time=now + FILE_TASK_DEFAULT_DURATION_SECONDS,
        )
        session.add(task)
        session.commit()

        return {
            "task_id": task.id,
            "provider": "native",  # Literal['native', ...]
            "start_time": task.start_time,
            "end_time": task.end_time,
            # Only download tasks support resume
            "supports_resume": transfer_mode == TransferMode.DOWNLOAD,
        }


def get_or_create_document_metadata(document: Document) -> DocumentMetadata:
    if document.metadata_record is None:
        document.metadata_record = DocumentMetadata()
    return document.metadata_record


def mark_document_modified(document: Document, username: str) -> None:
    get_or_create_document_metadata(document).last_modified_by_username = username


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
        "creator": metadata.creator_username,
        "last_modified_by": metadata.last_modified_by_username,
    }


class RequestGetDocumentInfoHandler(RequestHandler):
    """
    Handles the "get_document_info" action.
    """

    schema = {
        "type": "object",
        "properties": {"document_id": {"type": "string", "minLength": 1}},
        "required": ["document_id"],
    }

    require_auth = True

    def handle(self, handler: ConnectionHandler):

        document_id = handler.data.get("document_id")

        if not document_id:
            handler.conclude_request(400, {}, smsg.DOCUMENT_ID_REQUIRED)
            return

        with Session() as session:
            user = User.get_existing(session, handler.username)

            document = session.get(Document, document_id)

            if not document:
                handler.conclude_request(404, {}, smsg.DOCUMENT_NOT_FOUND)
                return Result(code=404, target=document_id, username=handler.username)

            try:
                document.get_latest_revision()
            except NoActiveRevisionsError:
                handler.conclude_request(
                    404, {}, "No active revisions found for this document"
                )
                return Result(code=404, target=document_id, username=handler.username)

            if not document.check_access_requirements(user, access_type="read"):
                handler.conclude_access_denial()
                return Result(code=403, target=document_id, username=handler.username)

            info_code = 0
            access_rules = []
            if Permissions.VIEW_ACCESS_RULES in user.all_permissions:
                access_rules = get_access_rules_list(
                    session,
                    target_type="document",
                    target_id=document.id,
                )
            else:
                info_code = 1  # No permission to view document access rules.

            data = {
                "document_id": document.id,
                "parent_id": document.folder_id,
                "title": document.title,
                "size": document.get_latest_revision().file.size,
                "created_time": document.created_time,
                "last_modified": document.get_latest_revision().created_time,
                "access_rules": access_rules,
                "info_code": info_code,
            }

            if Permissions.VIEW_METADATA in user.all_permissions:
                data["metadata"] = serialize_document_metadata(document)

            handler.conclude_request(200, data, "Document info retrieved successfully")
            return Result(code=0, target=document_id, username=handler.username)


class RequestGetDocumentAccessRulesHandler(RequestHandler):
    schema = {
        "type": "object",
        "properties": {"document_id": {"type": "string", "minLength": 1}},
        "required": ["document_id"],
        "additionalProperties": False,
    }
    require_auth = True

    def handle(self, handler: ConnectionHandler):

        document_id: str = handler.data["document_id"]

        with Session() as session:
            user = User.get_existing(session, handler.username)
            document = session.get(Document, document_id)

            if not document:
                handler.conclude_request(404, {}, smsg.DOCUMENT_NOT_FOUND)
                return Result(code=404, target=document_id, username=handler.username)

            if (
                not document.check_access_requirements(user, access_type="read")
                or Permissions.VIEW_ACCESS_RULES not in user.all_permissions
            ):
                handler.conclude_access_denial()
                return Result(code=403, target=document_id, username=handler.username)

            handler.conclude_request(
                200,
                {
                    "rules": get_access_rules_json(
                        session,
                        target_type="document",
                        target_id=document.id,
                    ),
                    "inherit": document.inherit,
                },
                "Document access rules retrieved successfully",
            )
            return Result(code=0, target=document_id, username=handler.username)


class RequestGetDocumentHandler(RequestHandler):
    """
    Handles the "get_document" action.
    """

    schema = {
        "type": "object",
        "properties": {"document_id": {"type": "string", "minLength": 1}},
        "required": ["document_id"],
        "additionalProperties": False,
    }

    require_auth = True

    def handle(self, handler: ConnectionHandler):
        document_id: str = handler.data["document_id"]

        with Session() as session:
            user = User.get_existing(session, handler.username)
            document = session.get(Document, document_id)

            if not document:
                handler.conclude_request(404, {}, smsg.DOCUMENT_NOT_FOUND)
                return Result(code=404, target=document_id, username=handler.username)

            if not document.check_access_requirements(user):
                handler.conclude_access_denial()
                return Result(code=403, target=document_id, username=handler.username)

            try:
                latest_revision = document.get_latest_revision()
            except NoActiveRevisionsError:
                handler.conclude_request(
                    404, {}, "No active revisions found for this document"
                )
                return Result(code=4041, target=document_id, username=handler.username)

            data = {
                "document_id": document.id,
                "title": document.title,
                "task_data": create_file_task(latest_revision.file),
            }

            handler.conclude_request(200, data, "Document successfully fetched")
            return Result(code=0, target=document_id, username=handler.username)


class RequestCreateDocumentHandler(RequestHandler):
    """
    Handles the "create_document" action.
    """

    schema = {
        "type": "object",
        "properties": {
            "folder_id": {"anyOf": [{"type": "string"}, {"type": "null"}]},
            "title": {"type": "string", "minLength": 1},
            "access_rules": {"type": "object"},
            "inherit_parent": {"type": "boolean"},
        },
        "required": ["title"],
        "additionalProperties": False,
    }

    require_auth = True

    def handle(self, handler: ConnectionHandler):
        folder_id = handler.data.get("folder_id") or ROOT_DIRECTORY_ID
        title = (handler.data.get("title") or "").strip()
        access_rules = handler.data.get("access_rules") or {}
        inherit_parent = handler.data.get("inherit_parent", True)

        if not title:
            handler.conclude_request(400, {}, smsg.DOCUMENT_TITLE_REQUIRED)
            return

        with Session() as session:
            user = User.get_existing(session, handler.username)

            if Permissions.CREATE_DOCUMENT not in user.all_permissions:
                handler.conclude_permission_denial()
                return Result(
                    code=403,
                    target=folder_id,
                    data={"title": title},
                    username=handler.username,
                )

            _folder, err_code, err_msg = get_target_folder_and_check_write(
                session, user, folder_id, Permissions.SUPER_CREATE_DOCUMENT
            )
            if err_code != 0:
                handler.conclude_request(err_code, {}, err_msg)
                return Result(
                    code=err_code,
                    target=folder_id,
                    data={"title": title},
                    username=handler.username,
                )

            has_conflict, err_code, err_data, err_msg = handle_name_duplicate(
                session, user, folder_id, title
            )
            if has_conflict:
                handler.conclude_request(err_code, err_data, err_msg)
                return Result(
                    code=err_code,
                    target=folder_id,
                    data={
                        "title": title,
                        "duplicate_id": err_data.get("duplicate_id"),
                    },
                    username=handler.username,
                )

            today = datetime.date.today()
            file_id = secrets.token_hex(32)
            real_filename = secrets.token_hex(32)

            new_file = File(
                id=file_id,
                path=f"content/files/{today.year}/{today.month}/{real_filename}",
            )
            new_document = Document(
                id=secrets.token_hex(32),
                title=title,
                folder_id=folder_id,
            )
            new_document.metadata_record = DocumentMetadata(
                creator_username=user.username,
                last_modified_by_username=user.username,
            )
            new_revision = DocumentRevision(file_id=new_file.id)
            new_document.revisions.append(new_revision)
            session.add(new_file)
            session.add(new_document)
            session.add(new_revision)

            try:
                if not apply_access_rules(
                    new_document, access_rules, user, inherit_parent
                ):
                    session.rollback()
                    handler.conclude_access_denial()
                    return Result(
                        code=403,
                        target=folder_id,
                        data={"title": title},
                        username=handler.username,
                    )

                new_document.current_revision = new_revision
                session.commit()

                task_data = create_file_task(
                    new_revision.file, transfer_mode=TransferMode.UPLOAD
                )
                handler.conclude_request(
                    200,
                    {"document_id": new_document.id, "task_data": task_data},
                    "Task successfully created",
                )

                return Result(
                    code=0,
                    target=folder_id,
                    data={"title": title},
                    username=handler.username,
                )

            except (ValueError, jsonschema.ValidationError) as exc:
                session.rollback()
                handler.conclude_request(
                    400, {}, f"Set access rules failed: {str(exc)}"
                )
                return Result(
                    code=400,
                    target=folder_id,
                    data={"title": title},
                    username=handler.username,
                )


class RequestUploadDocumentHandler(RequestHandler):
    """
    Handles the "upload_document" action.
    """

    schema = {
        "type": "object",
        "properties": {
            "document_id": {"type": "string", "minLength": 1},
            "parent_revision_id": {
                "anyOf": [
                    {
                        "type": "string",
                        "minLength": 1,
                        "maxLength": 64,
                    },
                    {"type": "null"},
                ]
            },
        },
        "required": ["document_id"],
        "additionalProperties": False,
    }

    require_auth = True

    def handle(self, handler: ConnectionHandler):
        document_id = handler.data["document_id"]

        with Session() as session:
            document = session.get(Document, document_id)
            this_user = User.get_existing(session, handler.username)

            if document:
                if not document.check_access_requirements(
                    this_user, access_type="write"
                ):
                    handler.conclude_access_denial()
                    return Result(
                        code=403, target=document_id, username=handler.username
                    )

                today = datetime.date.today()

                file_id = secrets.token_hex(32)
                real_filename = secrets.token_hex(32)

                new_file = File(
                    id=file_id,
                    path=f"content/files/{today.year}/{today.month}/{real_filename}",
                )

                if "parent_revision_id" in handler.data:
                    parent_revision_id = handler.data["parent_revision_id"]

                    # Validate the provided parent_revision_id if it's not null
                    if parent_revision_id and parent_revision_id not in [
                        rev.id for rev in document.revisions
                    ]:
                        handler.conclude_request(
                            400,
                            {},
                            "Parent revision does not exist or does not belong to this document",
                        )
                        return Result(
                            code=400, target=document_id, username=handler.username
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
                mark_document_modified(document, this_user.username)

                document.current_revision = new_revision
                session.commit()

            else:
                handler.conclude_request(404, {}, smsg.DOCUMENT_NOT_FOUND)
                return Result(code=404, target=document_id, username=handler.username)

            task_data = create_file_task(new_file, TransferMode.UPLOAD)

        handler.conclude_request(
            200, {"task_data": task_data}, "Task successfully created"
        )
        return Result(
            code=0, target=document_id, data=task_data, username=handler.username
        )


class RequestDeleteDocumentHandler(RequestHandler):
    """
    Handles the "delete_document" action.
    """

    schema = {
        "type": "object",
        "properties": {
            "document_id": {"type": "string", "minLength": 1},
        },
        "required": ["document_id"],
        "additionalProperties": False,
    }

    require_auth = True

    def handle(self, handler: ConnectionHandler):
        document_id = handler.data["document_id"]

        with Session() as session:
            user = User.get_existing(session, handler.username)
            document = session.get(Document, document_id)

            if not document:
                handler.conclude_request(404, {}, smsg.DOCUMENT_NOT_FOUND)
                return Result(code=404, target=document_id, username=handler.username)

            if (
                Permissions.DELETE_DOCUMENT not in user.all_permissions
                or not document.check_access_requirements(user, access_type="write")
            ):
                handler.conclude_access_denial()
                return Result(code=403, target=document_id, username=handler.username)

            document.status = EntityStatus.DELETED
            document.status_operation_id = (
                f"OP_DEL_{secrets.token_hex(8)}_{int(time.time())}"
            )
            mark_document_modified(document, user.username)
            session.commit()

        handler.conclude_request(200, {}, "Document successfully deleted")
        return Result(code=0, target=document_id, username=handler.username)


class RequestRenameDocumentHandler(RequestHandler):
    """
    Handles the "rename_document" action.
    """

    schema = {
        "type": "object",
        "properties": {
            "document_id": {"type": "string", "minLength": 1},
            "new_title": {"type": "string", "minLength": 1},
        },
        "required": ["document_id", "new_title"],
        "additionalProperties": False,
    }

    require_auth = True

    def handle(self, handler: ConnectionHandler):

        # Parse the directory renaming request
        document_id: str = handler.data["document_id"]
        new_title: str = handler.data["new_title"]

        with Session() as session:
            this_user = User.get_existing(session, handler.username)
            document = session.get(Document, document_id)

            if not document:
                handler.conclude_request(404, {}, smsg.DOCUMENT_NOT_FOUND)
                return Result(code=404, target=document_id, username=handler.username)

            parent_id = document.folder_id or ROOT_DIRECTORY_ID
            session.query(Folder).with_for_update().filter_by(id=parent_id).first()

            if (
                Permissions.RENAME_DOCUMENT not in this_user.all_permissions
                or not document.check_access_requirements(this_user, "write")
            ):
                handler.conclude_access_denial()
                return Result(code=403, target=document_id, username=handler.username)

            if document.title == new_title:
                handler.conclude_request(
                    **{
                        "code": 400,
                        "message": "New name is the same as the current name",
                        "data": {},
                    }
                )
                return

            has_conflict, err_code, err_data, err_msg = handle_name_duplicate(
                session, this_user, document.folder_id, new_title
            )
            if has_conflict:
                err_data_filtered = {k: v for k, v in err_data.items() if k != "entity"}
                handler.conclude_request(err_code, err_data_filtered, err_msg)
                if "duplicate_id" in err_data_filtered:
                    return Result(
                        code=err_code,
                        target=document.folder_id,
                        data={
                            "title": document.title,
                            "duplicate_id": err_data_filtered["duplicate_id"],
                        },
                        username=handler.username,
                    )
                return Result(
                    code=err_code, target=document.folder_id, username=handler.username
                )

            document.title = new_title
            mark_document_modified(document, this_user.username)
            session.commit()

            handler.conclude_request(
                **{
                    "code": 200,
                    "message": "Document renamed successfully",
                    "data": {},
                }
            )
            return Result(code=0, target=document_id, username=handler.username)


class RequestDownloadFileHandler(RequestHandler):
    """
    Handles the "download_file" action.
    """

    schema = {
        "type": "object",
        "properties": {
            "task_id": {"type": "string", "minLength": 1},
            "offset": {"type": "integer", "minimum": 0},
        },
        "required": ["task_id"],
        "additionalProperties": False,
    }

    def handle(self, handler: ConnectionHandler):
        task_id: str = handler.data["task_id"]
        offset: int = handler.data.get("offset", 0)

        with Session() as session:
            task = session.get(FileTask, task_id)
            if not task:
                handler.conclude_request(404, {}, smsg.TASK_NOT_FOUND)
                return

            if task.status != 0 or task.mode != 0:
                handler.conclude_request(
                    400, {}, "Task is not in a valid state for download"
                )
                return

            if task.start_time > time.time() or (
                task.end_time and task.end_time < time.time()
            ):
                handler.conclude_request(
                    400, {}, "Task is either not started yet or has already ended"
                )
                return

        # The server still needs to send one more response.
        handler.send_file(task_id, offset)


class RequestUploadFileHandler(RequestHandler):
    """
    Handles the "upload_file" action.
    """

    schema = {
        "type": "object",
        "properties": {
            "task_id": {"type": "string", "minLength": 1},
        },
        "required": ["task_id"],
        "additionalProperties": False,
    }

    def handle(self, handler: ConnectionHandler):
        task_id = handler.data["task_id"]

        with Session() as session:
            task = session.get(FileTask, task_id)
            if not task:
                handler.conclude_request(404, {}, smsg.TASK_NOT_FOUND)
                return

            if task.status != 0 or task.mode != 1:
                handler.conclude_request(
                    400, {}, "Task is not in a valid state for upload"
                )
                return

            if task.start_time > time.time() or (
                task.end_time and task.end_time < time.time()
            ):
                handler.conclude_request(
                    400, {}, "Task is either not started yet or has already ended"
                )
                return

        # The server needs to send one response.
        handler.receive_file(task_id)


class RequestSetDocumentRulesHandler(RequestHandler):
    """
    Handles the "set_document_rules" action.
    """

    schema = {
        "type": "object",
        "properties": {
            "document_id": {"type": "string", "minLength": 1},
            "access_rules": {
                "type": "object",
                "properties": {},
                "additionalProperties": {"type": "array", "items": {}},
            },
            "inherit_parent": {"type": "boolean"},
        },
        "required": ["document_id", "access_rules"],
        "additionalProperties": False,
    }

    require_auth = True

    def handle(self, handler: ConnectionHandler):
        """
        Handles the document access rules setting request from the client.
        """
        document_id: str = handler.data["document_id"]
        access_rules_to_apply: dict = handler.data["access_rules"]
        inherit_parent: bool = handler.data.get("inherit_parent", True)

        if not handler.username:
            handler.conclude_request(401, {}, smsg.AUTHENTICATION_REQUIRED)
            return Result(code=401, target=document_id)

        with Session() as session:
            user = User.get_existing(session, handler.username)

            document = session.get(Document, document_id)

            if not document:
                handler.conclude_request(404, {}, smsg.DOCUMENT_NOT_FOUND)
                return Result(code=404, target=document_id, username=handler.username)

            if Permissions.SET_ACCESS_RULES not in user.all_permissions:
                handler.conclude_request(403, {}, smsg.ACCESS_DENIED_SET_ACCESS_RULES)
                return Result(code=403, target=document_id, username=handler.username)

            if not document.check_access_requirements(user, access_type="manage"):
                handler.conclude_access_denial()
                return Result(code=403, target=document_id, username=handler.username)

            try:
                if apply_access_rules(
                    document, access_rules_to_apply, user, inherit_parent
                ):
                    mark_document_modified(document, user.username)
                    session.commit()
                    handler.conclude_request(200, {}, "Set access rules successfully")
                    return Result(code=0, target=document_id, username=handler.username)
                else:
                    session.rollback()
                    handler.conclude_access_denial()
                    return Result(
                        code=403, target=document_id, username=handler.username
                    )
            except (ValueError, jsonschema.ValidationError) as exc:
                session.rollback()
                handler.conclude_request(
                    400, {}, f"Set access rules failed: {str(exc)}"
                )
                return Result(code=400, target=document_id, username=handler.username)


class RequestMoveDocumentHandler(RequestHandler):
    """
    Handles the "move_document" action.
    """

    schema = {
        "type": "object",
        "properties": {
            "document_id": {"type": "string", "minLength": 1},
            "target_folder_id": {"anyOf": [{"type": "string"}, {"type": "null"}]},
        },
        "required": ["document_id"],  # , "target_folder_id"
        "additionalProperties": False,
    }

    require_auth = True

    def handle(self, handler: ConnectionHandler):

        document_id: str = handler.data["document_id"]
        target_folder_id: str | None = handler.data.get("target_folder_id")

        if not target_folder_id:
            target_folder_id = ROOT_DIRECTORY_ID

        with Session() as session:
            user = User.get_existing(session, handler.username)

            if Permissions.MOVE not in user.all_permissions:
                handler.conclude_request(403, {}, smsg.ACCESS_DENIED_MOVE_DOCUMENT)
                return Result(
                    code=403,
                    target=document_id,
                    data={"target_folder_id": target_folder_id},
                    username=handler.username,
                )

            document = session.get(Document, document_id)
            if not document:
                handler.conclude_request(
                    **{
                        "code": 404,
                        "message": smsg.TARGET_DOCUMENT_NOT_FOUND,
                        "data": {},
                    }
                )
                return Result(
                    code=404,
                    target=document_id,
                    data={"target_folder_id": target_folder_id},
                    username=handler.username,
                )

            if document.folder_id == target_folder_id:
                handler.conclude_request(400, {}, smsg.CANNOT_MOVE_TO_SAME_FOLDER)
                return Result(
                    code=400,
                    target=document_id,
                    data={"target_folder_id": target_folder_id},
                    username=handler.username,
                )

            if not document.check_access_requirements(user, "move"):
                handler.conclude_request(403, {}, smsg.ACCESS_DENIED_MOVE_DOCUMENT)
                return Result(
                    code=403,
                    target=document_id,
                    data={"target_folder_id": target_folder_id},
                    username=handler.username,
                )

            target_folder = (
                session.query(Folder)
                .with_for_update()
                .filter_by(id=target_folder_id)
                .first()
            )
            if not target_folder:
                handler.conclude_request(
                    **{
                        "code": 404,
                        "message": smsg.TARGET_DIRECTORY_NOT_FOUND,
                        "data": {},
                    }
                )
                return Result(
                    code=404,
                    target=document_id,
                    data={"target_folder_id": target_folder_id},
                    username=handler.username,
                )

            if not target_folder.check_access_requirements(user, "write"):
                if (
                    target_folder_id == ROOT_DIRECTORY_ID
                    and Permissions.SUPER_CREATE_DOCUMENT in user.all_permissions
                ):
                    pass
                else:
                    handler.conclude_request(
                        403, {}, smsg.ACCESS_DENIED_WRITE_DIRECTORY
                    )
                    return Result(
                        code=403,
                        target=document_id,
                        data={"target_folder_id": target_folder_id},
                        username=handler.username,
                    )

            has_conflict, err_code, err_data, err_msg = handle_name_duplicate(
                session, user, target_folder_id, document.title
            )
            if has_conflict:
                err_data_filtered = {k: v for k, v in err_data.items() if k != "entity"}
                handler.conclude_request(err_code, err_data_filtered, err_msg)
                if "duplicate_id" in err_data_filtered:
                    return Result(
                        code=err_code,
                        target=document.folder_id,
                        data={
                            "title": document.title,
                            "duplicate_id": err_data_filtered["duplicate_id"],
                        },
                        username=handler.username,
                    )
                return Result(
                    code=err_code, target=document.folder_id, username=handler.username
                )

            document.folder = target_folder
            mark_document_modified(document, user.username)

            session.commit()

        handler.conclude_request(200, {}, smsg.SUCCESS)
        return Result(
            code=0,
            target=document_id,
            data={"target_folder_id": target_folder_id},
            username=handler.username,
        )


class RequestPurgeDocumentHandler(RequestHandler):
    """
    Handles the "purge_document" action, which permanently deletes a document and all its revisions.

    This action is irreversible and should only be allowed for users with special permissions.
    """

    schema = {
        "type": "object",
        "properties": {
            "document_id": {"type": "string", "minLength": 1},
        },
        "required": ["document_id"],
        "additionalProperties": False,
    }

    require_auth = True

    def handle(self, handler: ConnectionHandler):
        doc_id = handler.data["document_id"]
        with Session() as session:
            user = User.get_existing(session, handler.username)

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

            if not document.check_access_requirements(user, "write"):
                handler.conclude_access_denial()
                return

            document.delete_all_revisions(do_commit=False)
            mark_document_modified(document, user.username)
            session.delete(document)
            session.commit()

        handler.conclude_request(200, {}, "Document permanently deleted")
        return Result(code=0, target=doc_id, username=handler.username)


class RequestRestoreDocumentHandler(RequestHandler):
    """
    Handles the "restore_document" action.
    Restores a marked-as-deleted document. Supports renaming and moving to a
    new folder during restoration. Maps virtual ROOT_DIRECTORY_ID to database None.
    """

    schema = {
        "type": "object",
        "properties": {
            "document_id": {"type": "string", "minLength": 1},
            "target_folder_id": {"anyOf": [{"type": "string"}, {"type": "null"}]},
            "new_title": {"type": "string", "minLength": 1},
        },
        "required": ["document_id"],
        "additionalProperties": False,
    }

    require_auth = True

    def handle(self, handler: ConnectionHandler):
        doc_id = handler.data["document_id"]

        target_folder_provided = "target_folder_id" in handler.data
        target_folder_id: str | None = handler.data.get("target_folder_id")
        new_title = handler.data.get("new_title")

        with Session() as session:
            user = User.get_existing(session, handler.username)

            if Permissions.RESTORE not in user.all_permissions:
                handler.conclude_permission_denial()
                return Result(code=403, target=doc_id, username=handler.username)

            document = session.get(
                Document, doc_id, execution_options={"include_deleted": True}
            )

            if not document or document.status != EntityStatus.DELETED:
                handler.conclude_request(404, {}, smsg.DELETED_DOCUMENT_NOT_FOUND)
                return Result(code=404, target=doc_id, username=handler.username)

            if not document.check_access_requirements(user, "write"):
                handler.conclude_access_denial()
                return Result(code=403, target=doc_id, username=handler.username)

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
                return Result(code=404, target=db_folder_id, username=handler.username)

            if not target_folder.check_access_requirements(user, "write"):
                handler.conclude_access_denial()
                return Result(code=403, target=db_folder_id, username=handler.username)

            if target_folder.status != EntityStatus.OK:
                handler.conclude_request(
                    409,
                    {"folder_id": db_folder_id},
                    "Cannot restore: Target folder is deleted. Restore it first.",
                )
                return Result(code=409, target=doc_id, username=handler.username)

            existing_conflict = (
                session.query(Document)
                .with_for_update()
                .filter(
                    Document.folder_id == db_folder_id,
                    Document.title == final_title,
                    Document.status == EntityStatus.OK,
                )
                .first()
                or session.query(Folder)
                .with_for_update()
                .filter(
                    Folder.parent_id == db_folder_id,
                    Folder.name == final_title,
                    Folder.status == EntityStatus.OK,
                )
                .first()
            )

            if existing_conflict:
                handler.conclude_request(
                    409,
                    {"conflict_id": existing_conflict.id},
                    f"Conflict: An active item named '{final_title}' already exists in the destination.",
                )
                return Result(code=409, target=doc_id, username=handler.username)

            document.status = EntityStatus.OK
            document.status_operation_id = None
            document.title = final_title
            document.folder_id = db_folder_id
            mark_document_modified(document, user.username)

            session.commit()

            handler.conclude_request(
                200,
                {
                    "title": final_title,
                    "folder_id": db_folder_id,
                },
                "Document successfully restored",
            )
            return Result(code=0, target=doc_id, username=handler.username)


class RequestSetDocumentTagsHandler(RequestHandler):
    schema = {
        "type": "object",
        "properties": {
            "document_id": {"type": "string", "minLength": 1},
            "tags": {
                "type": "array",
                "maxItems": 128,
                "items": {"type": "string", "minLength": 1, "maxLength": 255},
            },
        },
        "required": ["document_id", "tags"],
        "additionalProperties": False,
    }

    require_auth = True

    def handle(self, handler: ConnectionHandler):
        document_id: str = handler.data["document_id"]

        normalized_tags = []
        seen_tags = set()
        for raw_tag in handler.data["tags"]:
            tag = raw_tag.strip()
            if not tag:
                handler.conclude_request(400, {}, "Tags cannot be blank")
                return Result(code=400, target=document_id, username=handler.username)
            if tag not in seen_tags:
                normalized_tags.append(tag)
                seen_tags.add(tag)

        with Session() as session:
            user = User.get_existing(session, handler.username)
            document = session.get(Document, document_id)

            if not document:
                handler.conclude_request(404, {}, smsg.DOCUMENT_NOT_FOUND)
                return Result(code=404, target=document_id, username=handler.username)

            if (
                Permissions.SET_METADATA_TAGS not in user.all_permissions
                or not document.check_access_requirements(user, access_type="write")
            ):
                handler.conclude_access_denial()
                return Result(code=403, target=document_id, username=handler.username)

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

            metadata.last_modified_by_username = user.username
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
                username=handler.username,
            )

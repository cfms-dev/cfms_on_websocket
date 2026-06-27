import secrets
import time
from itertools import batched
from typing import Optional

import jsonschema
from sqlalchemy import func, literal, select
from sqlalchemy.orm import joinedload, raiseload, selectinload

from include.config.constants import QUERY_CHUNK_SIZE, ROOT_DIRECTORY_ID
from include.database.models.documents import (
    Document,
    DocumentRevision,
    EntityStatus,
    Folder,
)
from include.database.models.files import File
from include.database.models.identity import User
from include.database.session import Session
from include.domains.access.authorization.access_rules import apply_access_rules
from include.domains.access.permissions import Permissions
from include.domains.documents.commands.bulk_purge import purge_documents_bulk
from include.domains.documents.commands.name_conflicts import (
    handle_name_duplicate,
)
from include.domains.documents.queries.deletion_tree import fetch_subtree_for_deletion
from include.messages import Messages as smsg
from include.transport.connection import ConnectionHandler
from include.transport.request_handler import RequestHandler


def _fetch_latest_active_revisions_by_document(
    session, document_ids: list[str]
) -> dict[str, DocumentRevision]:
    if not document_ids:
        return {}

    revision_ids_by_document: dict[str, str] = {}
    document_table = Document.__table__
    revision_table = DocumentRevision.__table__
    file_table = File.__table__

    for chunk in batched(document_ids, QUERY_CHUNK_SIZE):
        chunk_ids = list(chunk)
        current_chain_anchor = (
            select(
                document_table.c.id.label("document_id"),
                revision_table.c.id.label("revision_id"),
                revision_table.c.created_time.label("created_time"),
                revision_table.c.file_id.label("file_id"),
                revision_table.c.parent_revision_id.label("parent_revision_id"),
                file_table.c.active.label("file_active"),
                literal(0).label("depth"),
            )
            .select_from(
                document_table.join(
                    revision_table,
                    document_table.c.current_revision_id == revision_table.c.id,
                ).join(file_table, revision_table.c.file_id == file_table.c.id)
            )
            .where(document_table.c.id.in_(chunk_ids))
        )
        current_chain = current_chain_anchor.cte(
            "current_revision_chain", recursive=True
        )
        parent_revision = revision_table.alias("parent_revision")
        parent_file = file_table.alias("parent_file")
        current_chain = current_chain.union_all(
            select(
                current_chain.c.document_id,
                parent_revision.c.id,
                parent_revision.c.created_time,
                parent_revision.c.file_id,
                parent_revision.c.parent_revision_id,
                parent_file.c.active,
                (current_chain.c.depth + 1).label("depth"),
            ).select_from(
                current_chain.join(
                    parent_revision,
                    current_chain.c.parent_revision_id == parent_revision.c.id,
                ).join(parent_file, parent_revision.c.file_id == parent_file.c.id)
            )
        )
        active_current_chain = (
            select(
                current_chain.c.document_id,
                current_chain.c.revision_id,
                func.row_number()
                .over(
                    partition_by=current_chain.c.document_id,
                    order_by=current_chain.c.depth,
                )
                .label("row_number"),
            )
            .where(current_chain.c.file_active.is_(True))
            .subquery()
        )
        current_chain_rows = session.execute(
            select(
                active_current_chain.c.document_id,
                active_current_chain.c.revision_id,
            ).where(active_current_chain.c.row_number == 1)
        ).all()
        for document_id, revision_id in current_chain_rows:
            revision_ids_by_document[document_id] = revision_id

        fallback_document_ids = [
            document_id
            for document_id in chunk_ids
            if document_id not in revision_ids_by_document
        ]
        if not fallback_document_ids:
            continue

        active_revisions = (
            select(
                revision_table.c.document_id,
                revision_table.c.id.label("revision_id"),
                func.row_number()
                .over(
                    partition_by=revision_table.c.document_id,
                    order_by=revision_table.c.created_time.desc(),
                )
                .label("row_number"),
            )
            .select_from(
                revision_table.join(
                    file_table, revision_table.c.file_id == file_table.c.id
                )
            )
            .where(
                revision_table.c.document_id.in_(fallback_document_ids),
                file_table.c.active.is_(True),
            )
            .subquery()
        )
        fallback_rows = session.execute(
            select(
                active_revisions.c.document_id, active_revisions.c.revision_id
            ).where(active_revisions.c.row_number == 1)
        ).all()
        for document_id, revision_id in fallback_rows:
            revision_ids_by_document[document_id] = revision_id

    if not revision_ids_by_document:
        return {}

    revisions: list[DocumentRevision] = []
    revision_ids = list(revision_ids_by_document.values())
    for chunk in batched(revision_ids, QUERY_CHUNK_SIZE):
        revisions.extend(
            session.query(DocumentRevision)
            .options(joinedload(DocumentRevision.file), raiseload("*"))
            .filter(DocumentRevision.id.in_(list(chunk)))
            .all()
        )

    revisions_by_id = {revision.id: revision for revision in revisions}
    return {
        document_id: revisions_by_id[revision_id]
        for document_id, revision_id in revision_ids_by_document.items()
        if revision_id in revisions_by_id
    }


class RequestListDirectoryHandler(RequestHandler):
    """
    Handles directory listing requests.
    This util processes a directory listing request by generating a list of files and directories in the specified directory.
    It sends an appropriate response back to the client, indicating success or failure.
    Args:
        handler (ConnectionHandler): The connection handler containing request data and methods for responding.
    Response Codes:
        200 - Directory listing successful, returns a list of files and directories in the response data.
        400 - Invalid request.
        403 - Invalid user or token.
        404 - Directory not found.
        500 - Internal server error, with the exception message.
    """

    schema = {
        "type": "object",
        "properties": {"folder_id": {"anyOf": [{"type": "string"}, {"type": "null"}]}},
        "required": ["folder_id"],
        "additionalProperties": False,
    }

    require_auth = True

    def handle(self, handler: ConnectionHandler):

        # Parse the directory listing request
        folder_id: Optional[str] = handler.data.get("folder_id")

        with Session() as session:
            this_user = User.get_existing(session, handler.username)

            # Determine parent folder and fetch children/documents
            if not folder_id:
                folder_id = ROOT_DIRECTORY_ID

            folder = (
                session.query(Folder)
                .options(selectinload(Folder.access_rules))
                .filter(Folder.id == folder_id)
                .first()
            )
            if not folder:
                handler.conclude_request(404, {}, smsg.DIRECTORY_NOT_FOUND)
                return 404, folder_id, handler.username

            has_permission = (
                Permissions.SUPER_LIST_DIRECTORY in this_user.all_permissions
                or folder.check_access_requirements(this_user, "read")
            )

            if not has_permission:
                handler.conclude_access_denial()
                return 403, folder_id, handler.username

            children = (
                session.query(Folder)
                .options(raiseload("*"))
                .filter(Folder.parent_id == folder_id)
                .all()
            )
            documents = (
                session.query(Document)
                .options(raiseload("*"))
                .filter(Document.folder_id == folder_id)
                .all()
            )
            latest_revisions_by_document = _fetch_latest_active_revisions_by_document(
                session, [document.id for document in documents]
            )

            parent_id = folder.parent_id

            response = {
                "code": 200,
                "message": "Directory listing successful",
                "data": {
                    "parent_id": parent_id,
                    "documents": [
                        {
                            "id": document.id,
                            "title": document.title,
                            "created_time": document.created_time,
                            "last_modified": last_revision.created_time,
                            "sha256": last_revision.file.sha256,
                            "size": last_revision.file.size,
                        }
                        for document in documents
                        if (
                            last_revision := latest_revisions_by_document.get(
                                document.id
                            )
                        )
                    ],
                    "folders": [
                        {
                            "id": child.id,
                            "name": child.name,
                            "created_time": child.created_time,
                        }
                        for child in children
                    ],
                },
            }

        # Send the response back to the client
        handler.conclude_request(**response)
        return 200, folder_id, handler.username


class RequestGetDirectoryInfoHandler(RequestHandler):
    """
    Handles directory information requests.
    This util processes a directory information request by retrieving information about the specified directory.
    It sends an appropriate response back to the client, indicating success or failure.
    Args:
        handler (ConnectionHandler): The connection handler containing request data and methods for responding.
    Response Codes:
        200 - Directory info successful, returns directory info in the response data.
        400 - Invalid request.
        403 - Invalid user or token.
        404 - Directory not found.
        500 - Internal server error, with the exception message.
    """

    schema = {
        "type": "object",
        "properties": {"directory_id": {"type": "string", "minLength": 1}},
        "required": ["directory_id"],
        "additionalProperties": False,
    }

    require_auth = True

    def handle(self, handler: ConnectionHandler):

        directory_id: str = handler.data["directory_id"]

        if not directory_id:
            handler.conclude_request(400, {}, smsg.DIRECTORY_ID_REQUIRED)
            return

        with Session() as session:
            # require_auth ensures this
            user = User.get_existing(session, handler.username)

            directory = session.get(Folder, directory_id)

            if not directory:
                handler.conclude_request(404, {}, smsg.DIRECTORY_NOT_FOUND)
                return 404, directory_id, handler.username

            if not directory.check_access_requirements(user, access_type="read"):
                handler.conclude_access_denial()
                return 403, directory_id, handler.username

            info_code = 0
            ### generate access_rules text
            access_rules = []
            if Permissions.VIEW_ACCESS_RULES in user.all_permissions:
                for each_rule in directory.access_rules:
                    access_rules.append(
                        {
                            "rule_id": each_rule.id,
                            "rule_data": each_rule.rule_data,
                            "access_type": each_rule.access_type,
                        }
                    )
            else:
                info_code = 1  # 无权访问目录

            data = {
                "directory_id": directory.id,
                "count_of_child": directory.count_of_child,
                "parent_id": directory.parent_id,
                "name": directory.name,
                "created_time": directory.created_time,
                "access_rules": access_rules,
                "info_code": info_code,
            }

            handler.conclude_request(200, data, "Directory info retrieved successfully")
            return 0, directory_id, handler.username


class RequestGetDirectoryAccessRulesHandler(RequestHandler):
    schema = {
        "type": "object",
        "properties": {"directory_id": {"type": "string", "minLength": 1}},
        "required": ["directory_id"],
        "additionalProperties": False,
    }
    require_auth = True

    def handle(self, handler: ConnectionHandler):

        directory_id: str = handler.data["directory_id"]

        with Session() as session:
            user = User.get_existing(session, handler.username)
            directory = session.get(Folder, directory_id)

            if not directory:
                handler.conclude_request(404, {}, smsg.DIRECTORY_NOT_FOUND)
                return 404, directory_id, handler.username

            if (
                not directory.check_access_requirements(user, access_type="read")
                or Permissions.VIEW_ACCESS_RULES not in user.all_permissions
            ):
                handler.conclude_access_denial()
                return 403, directory_id, handler.username

            # generate access_rules
            access_rules: dict[str, list] = {}

            for each_rule in directory.access_rules:
                if each_rule.access_type not in access_rules:
                    access_rules[each_rule.access_type] = []
                access_rules[each_rule.access_type].append(each_rule.rule_data)

            handler.conclude_request(
                200,
                {"rules": access_rules, "inherit": directory.inherit},
                "Directory access rules retrieved successfully",
            )
            return 0, directory_id, handler.username


class RequestCreateDirectoryHandler(RequestHandler):
    """
    Handles directory creation requests.
    This util processes a directory creation request by creating a new directory in the specified parent directory.
    It sends an appropriate response back to the client, indicating success or failure.
    Args:
        handler (ConnectionHandler): The connection handler containing request data and methods for responding.
    Response Codes:
        200 - Directory created successfully, returns the created directory in the response data.
        400 - Invalid request.
        403 - Invalid user or token.
        404 - Parent directory not found.
        500 - Internal server error, with the exception message.
    """

    schema = {
        "type": "object",
        "properties": {
            "parent_id": {"anyOf": [{"type": "string"}, {"type": "null"}]},
            "name": {"type": "string", "minLength": 1},
            "access_rules": {
                "type": "object",
                "properties": {},
                "additionalProperties": {"type": "array", "items": {}},
            },
            "exists_ok": {"type": "boolean"},
            "inherit_parent": {"type": "boolean"},
        },
        "required": ["name"],
    }

    require_auth = True

    def handle(self, handler: ConnectionHandler):
        data = handler.data
        parent_id = data.get("parent_id")
        name = data["name"]
        access_rules = data.get("access_rules", {})
        exists_ok = data.get("exists_ok", False)
        inherit_parent = data.get("inherit_parent", True)

        if not parent_id:
            parent_id = ROOT_DIRECTORY_ID

        with Session() as session:
            this_user = User.get_existing(session, handler.username)

            if Permissions.CREATE_DIRECTORY not in this_user.all_permissions:
                handler.conclude_request(
                    403, {}, "You have no permissions to create directories"
                )
                return 403, parent_id, handler.username

            parent = (
                session.query(Folder).with_for_update().filter_by(id=parent_id).first()
            )
            if not parent:
                handler.conclude_request(404, {}, smsg.DIRECTORY_NOT_FOUND)
                return 404, parent_id, handler.username
            if not parent.check_access_requirements(this_user, "write"):
                if (
                    parent_id == ROOT_DIRECTORY_ID
                    and Permissions.SUPER_CREATE_DIRECTORY in this_user.all_permissions
                ):
                    # Allow super creation in root directory if global permission is given
                    pass
                else:
                    handler.conclude_access_denial()
                    return 403, parent_id, handler.username

            has_conflict, err_code, err_data, err_msg = handle_name_duplicate(
                session, this_user, parent_id, name
            )
            if has_conflict:
                if (
                    exists_ok
                    and err_data.get("type") == "directory"
                    and err_data.get("entity")
                ):
                    existing_folder = err_data["entity"]
                    handler.conclude_request(
                        200,
                        {
                            "id": existing_folder.id,
                            "name": existing_folder.name,
                            "last_modified": existing_folder.created_time,
                        },
                        "Directory already exists",
                    )
                    return 0, parent_id, handler.username
                else:
                    err_data_filtered = {
                        k: v for k, v in err_data.items() if k != "entity"
                    }
                    handler.conclude_request(err_code, err_data_filtered, err_msg)
                    if "duplicate_id" in err_data_filtered:
                        return (
                            err_code,
                            parent_id,
                            {
                                "name": name,
                                "duplicate_id": err_data_filtered["duplicate_id"],
                            },
                            handler.username,
                        )
                    return err_code, parent_id, handler.username

            folder = Folder(name=name, parent=parent)
            if not apply_access_rules(folder, access_rules, this_user, inherit_parent):
                session.rollback()
                handler.conclude_access_denial()
                return 403, parent_id, handler.username

            session.add(folder)
            session.commit()

            handler.conclude_request(
                200,
                {
                    "id": folder.id,
                    "name": folder.name,
                    "last_modified": folder.created_time,
                },
                "Directory created successfully",
            )
            return 0, parent_id, handler.username


class RequestDeleteDirectoryHandler(RequestHandler):
    """
    Handles directory deletion requests.
    This util processes a directory deletion request by deleting the specified directory.
    It sends an appropriate response back to the client, indicating success or failure.
    Args:
        handler (ConnectionHandler): The connection handler containing request data and methods for responding.
    Response Codes:
        200 - Directory deleted successfully.
        400 - Invalid request.
        403 - Invalid user or token.
        404 - Directory not found.
        500 - Internal server error, with the exception message.
    """

    schema = {
        "type": "object",
        "properties": {
            "folder_id": {"type": "string", "minLength": 1},
        },
        "required": ["folder_id"],
        "additionalProperties": False,
    }

    require_auth = True

    def handle(self, handler: ConnectionHandler):

        # Parse the directory deletion request
        folder_id = handler.data["folder_id"]  # Get the folder ID from the request data

        if folder_id == ROOT_DIRECTORY_ID:
            handler.conclude_request(404, {}, smsg.DIRECTORY_NOT_FOUND)
            return 404, folder_id, handler.username

        with Session() as session:
            this_user = User.get_existing(session, handler.username)
            folder = session.get(Folder, folder_id)
            if not folder:
                handler.conclude_request(404, {}, smsg.DIRECTORY_NOT_FOUND)
                return 404, folder_id, handler.username
            if (
                Permissions.DELETE_DIRECTORY not in this_user.all_permissions
                or not folder.check_access_requirements(this_user, "write")
            ):
                handler.conclude_access_denial()
                return 403, folder_id, handler.username

            operation_id = f"OP_DEL_{secrets.token_hex(8)}_{int(time.time())}"
            now = time.time()

            # analyze subtree, determine deletable items and protected items,
            # prepare for batch deletion
            (
                deletable_folder_ids,
                deletable_doc_ids,
                failed_items,
                protected_folder_ids,
                folder_map,
            ) = fetch_subtree_for_deletion(session, folder_id, this_user, now=now)

            # execute batch deletion in a transaction

            # 2a. mark documents for deletion in DB; failures are logged.
            for chunk in batched(list(deletable_doc_ids), QUERY_CHUNK_SIZE):
                session.query(Document).filter(Document.id.in_(list(chunk))).update(
                    {
                        "status": EntityStatus.DELETED,
                        "status_operation_id": operation_id,
                    },
                    synchronize_session=False,
                )

            # 2b. Mark folders as DELETED
            for chunk in batched(list(deletable_folder_ids), QUERY_CHUNK_SIZE):
                session.query(Folder).filter(Folder.id.in_(list(chunk))).update(
                    {
                        "status": EntityStatus.DELETED,
                        "status_operation_id": operation_id,
                    },
                    synchronize_session=False,
                )

            # 2c. Mark the root folder as DELETED
            root_fully_deletable = (
                len(protected_folder_ids) == 0 and len(failed_items) == 0
            )
            if root_fully_deletable:
                folder.status = EntityStatus.DELETED
                folder.status_operation_id = operation_id

            session.commit()

            # construct response based on deletion result
            if failed_items:
                handler.conclude_request(
                    207,  # 207 Multi-Status：partial success
                    {
                        "deleted_folders": list(deletable_folder_ids),
                        "deleted_documents": list(deletable_doc_ids),
                        "root_deleted": root_fully_deletable,
                        "failed": failed_items,
                    },
                    "Directory partially deleted: some items could not be removed due to insufficient permissions.",
                )
                return 207, folder_id, handler.username
            else:
                handler.conclude_request(
                    200, {}, "Directory marked as deleted successfully"
                )
                return 0, folder_id, handler.username


class RequestRenameDirectoryHandler(RequestHandler):
    """
    Handles directory renaming requests.
    This util processes a directory renaming request by updating the name of the specified directory.
    It sends an appropriate response back to the client, indicating success or failure.
    Args:
        handler (ConnectionHandler): The connection handler containing request data and methods for responding.
    Response Codes:
        200 - Directory renamed successfully.
        400 - Invalid request.
        403 - Invalid user or token.
        404 - Directory not found.
        500 - Internal server error, with the exception message.
    """

    schema = {
        "type": "object",
        "properties": {
            "folder_id": {"type": "string", "minLength": 1},
            "new_name": {"type": "string", "minLength": 1},
        },
        "required": ["folder_id", "new_name"],
        "additionalProperties": False,
    }

    require_auth = True

    def handle(self, handler: ConnectionHandler):

        # Parse the directory renaming request
        folder_id = handler.data["folder_id"]
        new_name = handler.data["new_name"]

        if folder_id == ROOT_DIRECTORY_ID:
            handler.conclude_request(404, {}, smsg.DIRECTORY_NOT_FOUND)
            return 404, folder_id, handler.username

        with Session() as session:
            this_user = User.get_existing(session, handler.username)

            folder = session.get(Folder, folder_id)
            if not folder:
                handler.conclude_request(404, {}, smsg.DIRECTORY_NOT_FOUND)
                return 404, folder_id, handler.username

            parent_id = folder.parent_id

            if parent_id:
                session.query(Folder).with_for_update().filter_by(id=parent_id).first()
            else:
                session.query(Folder).with_for_update().filter_by(
                    id=ROOT_DIRECTORY_ID
                ).first()

            if (
                Permissions.RENAME_DIRECTORY not in this_user.all_permissions
                or not folder.check_access_requirements(this_user, "write")
            ):
                handler.conclude_access_denial()
                return 403, folder_id, handler.username

            if folder.name == new_name:
                handler.conclude_request(
                    **{
                        "code": 400,
                        "message": "New name is the same as the current name",
                        "data": {},
                    }
                )
                return

            has_conflict, err_code, err_data, err_msg = handle_name_duplicate(
                session, this_user, folder.parent_id, new_name
            )
            if has_conflict:
                err_data_filtered = {k: v for k, v in err_data.items() if k != "entity"}
                handler.conclude_request(err_code, err_data_filtered, err_msg)
                if "duplicate_id" in err_data_filtered:
                    return (
                        err_code,
                        folder_id,
                        {
                            "title": new_name,
                            "duplicate_id": err_data_filtered["duplicate_id"],
                        },
                        handler.username,
                    )
                return err_code, folder_id, handler.username

            folder.name = new_name
            session.commit()

            handler.conclude_request(
                **{
                    "code": 200,
                    "message": "Directory renamed successfully",
                    "data": {},
                }
            )
            return 0, folder_id, handler.username


class RequestMoveDirectoryHandler(RequestHandler):
    schema = {
        "type": "object",
        "properties": {
            "folder_id": {"type": "string", "minLength": 1},
            "target_folder_id": {"anyOf": [{"type": "string"}, {"type": "null"}]},
        },
        "required": ["folder_id", "target_folder_id"],
        "additionalProperties": False,
    }

    require_auth = True

    def handle(self, handler: ConnectionHandler):

        folder_id: str = handler.data["folder_id"]
        target_folder_id: Optional[str] = handler.data.get("target_folder_id")

        if not target_folder_id:
            target_folder_id = ROOT_DIRECTORY_ID

        if folder_id == ROOT_DIRECTORY_ID:
            handler.conclude_request(404, {}, smsg.DIRECTORY_NOT_FOUND)
            return 404, folder_id, handler.username

        with Session() as session:
            user = User.get_existing(session, handler.username)

            if Permissions.MOVE not in user.all_permissions:
                handler.conclude_request(403, {}, smsg.ACCESS_DENIED_MOVE_DIRECTORY)
                return 403, folder_id, handler.username

            folder = session.get(Folder, folder_id)

            if not folder:
                handler.conclude_request(
                    **{
                        "code": 404,
                        "message": smsg.SUBJECT_DIRECTORY_NOT_FOUND,
                        "data": {},
                    }
                )
                return 404, folder_id, handler.username

            if not folder.check_access_requirements(user, "move"):
                handler.conclude_request(403, {}, smsg.ACCESS_DENIED_MOVE_DIRECTORY)
                return 403, folder_id, handler.username

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
                return 404, folder_id, handler.username

            if not target_folder.check_access_requirements(user, "write"):
                if (
                    target_folder_id == ROOT_DIRECTORY_ID
                    and Permissions.SUPER_CREATE_DIRECTORY in user.all_permissions
                ):
                    pass
                else:
                    handler.conclude_request(
                        403, {}, smsg.ACCESS_DENIED_WRITE_DIRECTORY
                    )
                    return 403, folder_id, handler.username

            # Check if target folder is a descendant of the folder being moved
            if target_folder.id == folder.id or target_folder.is_descendant_of(folder):
                handler.conclude_request(
                    400, {}, smsg.CANNOT_MOVE_DIRECTORY_INTO_SUBDIRECTORY
                )
                return 400, folder_id, handler.username

            has_conflict, err_code, err_data, err_msg = handle_name_duplicate(
                session, user, target_folder_id, folder.name
            )
            if has_conflict:
                err_data_filtered = {k: v for k, v in err_data.items() if k != "entity"}
                handler.conclude_request(err_code, err_data_filtered, err_msg)
                if "duplicate_id" in err_data_filtered:
                    return (
                        err_code,
                        folder_id,
                        {
                            "title": folder.name,
                            "duplicate_id": err_data_filtered["duplicate_id"],
                        },
                        handler.username,
                    )
                return err_code, folder_id, handler.username

            folder.parent = target_folder

            session.commit()

        handler.conclude_request(200, {}, smsg.SUCCESS)
        return 0, folder_id, handler.username


class RequestSetDirectoryRulesHandler(RequestHandler):
    """
    Handles the "set_directory_rules" action.
    """

    schema = {
        "type": "object",
        "properties": {
            "directory_id": {"type": "string", "minLength": 1},
            "access_rules": {
                "type": "object",
                "properties": {},
                "additionalProperties": {"type": "array", "items": {}},
            },
            "inherit_parent": {"type": "boolean"},
        },
        "required": ["directory_id", "access_rules"],
        "additionalProperties": False,
    }

    require_auth = True

    def handle(self, handler: ConnectionHandler):
        """
        Handles the directory access rules setting request from the client.
        """
        directory_id: str = handler.data["directory_id"]
        access_rules_to_apply: dict = handler.data["access_rules"]
        inherit_parent: bool = handler.data.get("inherit_parent", True)

        if not handler.username:
            handler.conclude_request(401, {}, smsg.AUTHENTICATION_REQUIRED)
            return 401, directory_id

        with Session() as session:
            user = User.get_existing(session, handler.username)

            directory = session.get(Folder, directory_id)

            if not directory:
                handler.conclude_request(404, {}, smsg.DIRECTORY_NOT_FOUND)
                return 404, directory_id, handler.username

            if Permissions.SET_ACCESS_RULES not in user.all_permissions:
                handler.conclude_request(403, {}, smsg.ACCESS_DENIED_SET_ACCESS_RULES)
                return 403, directory_id, handler.username

            if not directory.check_access_requirements(user, access_type="manage"):
                handler.conclude_access_denial()
                return 403, directory_id, handler.username

            try:
                if apply_access_rules(
                    directory, access_rules_to_apply, user, inherit_parent
                ):
                    session.commit()
                    handler.conclude_request(200, {}, "Set access rules successfully")
                    return 0, directory_id, handler.username
                else:
                    session.rollback()
                    handler.conclude_access_denial()
                    return 403, directory_id, handler.username
            except (ValueError, jsonschema.ValidationError) as exc:
                session.rollback()
                handler.conclude_request(
                    400, {}, f"Set access rules failed: {str(exc)}"
                )
                return 400, directory_id, handler.username


class RequestPurgeDirectoryHandler(RequestHandler):
    """
    Handles the "purge_directory" action.
    Permanently removes a directory, all its subdirectories, and all documents within.
    This action is irreversible.
    """

    schema = {
        "type": "object",
        "properties": {
            "folder_id": {"type": "string", "minLength": 1},
        },
        "required": ["folder_id"],
        "additionalProperties": False,
    }

    require_auth = True

    def handle(self, handler: ConnectionHandler):
        folder_id = handler.data["folder_id"]

        if folder_id == ROOT_DIRECTORY_ID:
            handler.conclude_request(403, {}, smsg.CANNOT_PURGE_ROOT_DIRECTORY)
            return 403, folder_id, handler.username

        with Session() as session:
            user = User.get_existing(session, handler.username)

            if Permissions.PURGE not in user.all_permissions:
                handler.conclude_permission_denial()
                return 403, folder_id, handler.username

            folder = session.get(
                Folder, folder_id, execution_options={"include_deleted": True}
            )

            if not folder:
                handler.conclude_request(404, {}, smsg.DIRECTORY_NOT_FOUND)
                return 404, folder_id, handler.username

            if folder.status != EntityStatus.DELETED:
                handler.conclude_request(
                    400, {}, "Directory must be marked as deleted before purging"
                )
                return 400, folder_id, handler.username

            if not folder.check_access_requirements(user, "write"):
                handler.conclude_access_denial()
                return 403, folder_id, handler.username

            try:
                (
                    all_folder_ids,
                    all_doc_ids,
                    failed_items,
                    _,
                    folder_map,
                ) = fetch_subtree_for_deletion(
                    session, folder_id, user, include_deleted=True
                )

                if failed_items:
                    handler.conclude_request(
                        403,
                        {"failed": failed_items},
                        "Some items in the directory cannot be purged due to insufficient permissions",
                    )
                    return 403, folder_id, handler.username

                session.autoflush = False

                if all_doc_ids:
                    purge_documents_bulk(session, list(all_doc_ids))

                if all_folder_ids:
                    for chunk in batched(all_folder_ids, QUERY_CHUNK_SIZE):
                        session.query(Folder).filter(Folder.id.in_(chunk)).delete(
                            synchronize_session=False
                        )

                session.delete(folder)
                session.commit()

                handler.conclude_request(
                    200,
                    {},
                    "Directory and all its contents have been permanently purged",
                )
                return 0, folder_id, handler.username

            finally:
                session.autoflush = True


class RequestRestoreDirectoryHandler(RequestHandler):
    """
    Handles the "restore_directory" action.
    Supports virtual ROOT_DIRECTORY_ID translation to database None.
    """

    schema = {
        "type": "object",
        "properties": {
            "folder_id": {"type": "string", "minLength": 1},
            "target_parent_id": {"type": ["string", "null"], "minLength": 1},
            "new_name": {"type": "string", "minLength": 1},
        },
        "required": ["folder_id"],
        "additionalProperties": False,
    }

    require_auth = True

    def handle(self, handler: ConnectionHandler):
        folder_id = handler.data["folder_id"]
        target_parent_provided = "target_parent_id" in handler.data
        target_parent_id = handler.data.get("target_parent_id")
        new_name = handler.data.get("new_name")

        if folder_id == ROOT_DIRECTORY_ID:
            handler.conclude_request(400, {}, smsg.CANNOT_RESTORE_ROOT_DIRECTORY)
            return 400, folder_id, handler.username

        with Session() as session:
            user = User.get_existing(session, handler.username)

            if Permissions.RESTORE not in user.all_permissions:
                handler.conclude_permission_denial()
                return 403, folder_id, handler.username

            folder = session.get(
                Folder, folder_id, execution_options={"include_deleted": True}
            )

            if not folder or folder.status != EntityStatus.DELETED:
                handler.conclude_request(404, {}, smsg.DELETED_DIRECTORY_NOT_FOUND)
                return 404, folder_id, handler.username

            if not folder.check_access_requirements(user, "write"):
                handler.conclude_access_denial()
                return 403, folder_id, handler.username

            if target_parent_provided:
                db_parent_id = target_parent_id or ROOT_DIRECTORY_ID
            else:
                db_parent_id = folder.parent_id or ROOT_DIRECTORY_ID

            final_name = new_name if new_name else folder.name

            target_parent = (
                session.query(Folder)
                .execution_options(include_deleted=True)
                .with_for_update()
                .filter_by(id=db_parent_id)
                .first()
            )
            if not target_parent or target_parent.status != EntityStatus.OK:
                handler.conclude_request(409, {}, smsg.TARGET_DIRECTORY_NOT_ACTIVE)
                return 409, db_parent_id, handler.username

            if not target_parent.check_access_requirements(user, "write"):
                handler.conclude_access_denial()
                return 403, db_parent_id, handler.username

            existing_conflict = (
                session.query(Folder)
                .with_for_update()
                .filter(
                    Folder.parent_id == db_parent_id,
                    Folder.name == final_name,
                    Folder.status == EntityStatus.OK,
                )
                .first()
                or session.query(Document)
                .with_for_update()
                .filter(
                    Document.folder_id == db_parent_id,
                    Document.title == final_name,
                    Document.status == EntityStatus.OK,
                )
                .first()
            )

            if existing_conflict:
                handler.conclude_request(
                    409, {"conflict_id": existing_conflict.id}, "Name conflict"
                )
                return 409, folder_id, handler.username

            op_id = folder.status_operation_id

            if op_id:
                # 批量恢复文档
                session.query(Document).execution_options(include_deleted=True).filter(
                    Document.status_operation_id == op_id,
                    Document.status == EntityStatus.DELETED,
                ).update(
                    {"status": EntityStatus.OK, "status_operation_id": None},
                    synchronize_session=False,
                )

                # 批量恢复文件夹
                session.query(Folder).execution_options(include_deleted=True).filter(
                    Folder.status_operation_id == op_id,
                    Folder.status == EntityStatus.DELETED,
                    Folder.id != folder.id,
                ).update(
                    {"status": EntityStatus.OK, "status_operation_id": None},
                    synchronize_session=False,
                )

            folder.status = EntityStatus.OK
            folder.status_operation_id = None
            folder.name = final_name
            folder.parent_id = db_parent_id

            session.commit()

            handler.conclude_request(
                200, {"parent_id": db_parent_id, "name": final_name}, smsg.SUCCESS
            )
            return 0, folder_id, handler.username


class RequestListDeletedItemsHandler(RequestHandler):
    """
    Handles the "list_deleted_items" action.
    Lists folders and documents that have been marked as deleted within
     a specific parent directory.
    """

    schema = {
        "type": "object",
        "properties": {
            "folder_id": {"type": "string", "minLength": 1},
        },
        "required": ["folder_id"],
        "additionalProperties": False,
    }

    require_auth = True

    def handle(self, handler: ConnectionHandler):
        parent_id = handler.data["folder_id"]

        with Session() as session:
            user = User.get_existing(session, handler.username)

            if Permissions.LIST_DELETED_ITEMS not in user.all_permissions:
                handler.conclude_permission_denial()
                return 403, parent_id, handler.username

            db_parent_id = parent_id

            parent_folder = session.get(
                Folder,
                db_parent_id,
                execution_options={"include_deleted": True},
            )

            if not parent_folder:
                handler.conclude_request(404, {}, smsg.DIRECTORY_NOT_FOUND)
                return 404, parent_id, handler.username

            if (
                Permissions.SUPER_LIST_DIRECTORY not in user.all_permissions
                and not parent_folder.check_access_requirements(user, "read")
            ):
                handler.conclude_access_denial()
                return 403, parent_id, handler.username

            deleted_folders = (
                session.query(Folder)
                .execution_options(include_deleted=True)
                .filter(
                    Folder.parent_id == db_parent_id,
                    Folder.status == EntityStatus.DELETED,
                )
                .all()
            )

            deleted_documents = (
                session.query(Document)
                .execution_options(include_deleted=True)
                .filter(
                    Document.folder_id == db_parent_id,
                    Document.status == EntityStatus.DELETED,
                )
                .all()
            )

            result_data = {
                "folders": [
                    {
                        "id": f.id,
                        "name": f.name,
                        "created_time": f.created_time,
                        "status_operation_id": f.status_operation_id,
                    }
                    for f in deleted_folders
                ],
                "documents": [
                    {
                        "id": d.id,
                        "title": d.title,
                        "created_time": d.created_time,
                        "status_operation_id": d.status_operation_id,
                    }
                    for d in deleted_documents
                ],
                "parent_id": parent_id,
            }

            handler.conclude_request(200, result_data, "Deleted items retrieved")
            return 0, parent_id, handler.username

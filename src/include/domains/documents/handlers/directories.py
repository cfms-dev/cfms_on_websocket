import secrets
import time
from itertools import batched
from typing import Any

import jsonschema
from pydantic import ConfigDict

from include.config.constants import QUERY_CHUNK_SIZE, ROOT_DIRECTORY_ID
from include.database.models.documents import (
    EntityStatus,
    Folder,
    Node,
)
from include.database.models.identity import User
from include.database.session import Session
from include.domains.access.authorization.access_rules import apply_access_rules
from include.domains.access.authorization.compiled_rules import (
    delete_compiled_access_rules_for_targets,
    get_access_rules_dict,
    get_access_rules_list_from_map,
)
from include.domains.access.authorization.evaluation import (
    FolderAccessEvaluationContext,
    check_access_requirements,
    load_folder_access_evaluation_context,
)
from include.domains.access.permissions import Permissions
from include.domains.documents.commands.bulk_purge import purge_documents_bulk
from include.domains.documents.commands.file_tasks import cancel_file_tasks_for_files
from include.domains.documents.commands.name_conflicts import (
    NodeNameConflictError,
    describe_node_name_conflict,
    describe_subtree_restore_name_conflict,
    node_name_mutation,
)
from include.domains.documents.file_task_signals import publish_cancelled_file_tasks
from include.domains.documents.handlers.name_conflict_responses import (
    respond_to_node_name_conflict,
)
from include.domains.documents.queries.deletion_tree import fetch_subtree_for_deletion
from include.domains.documents.queries.file_references import (
    find_unreachable_document_file_ids,
)
from include.domains.documents.queries.listing import (
    count_active_directory_children,
    directory_cursor_key,
    fetch_deleted_listing_items,
    fetch_directory_listing_items,
)
from include.domains.pagination import (
    CursorError,
    PaginationCursor,
    PaginationCursorToken,
    PaginationPageSize,
    get_page_size,
    make_cursor_response,
)
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

_AccessRules = dict[str, list[Any]]


class _ListDirectoryRequest(RequestDataModel):
    folder_id: str | None
    page_size: Omittable[PaginationPageSize] = REQUEST_UNSET
    cursor: PaginationCursorToken | None = None


class _DirectoryIDRequest(RequestDataModel):
    directory_id: NonEmptyString


class _CreateDirectoryRequest(RequestDataModel):
    model_config = ConfigDict(
        strict=True,
        validate_default=True,
        extra="allow",
    )

    parent_id: str | None = None
    name: NonEmptyString
    access_rules: Omittable[_AccessRules] = REQUEST_UNSET
    exists_ok: Omittable[bool] = REQUEST_UNSET
    inherit_parent: Omittable[bool] = REQUEST_UNSET


class _FolderIDRequest(RequestDataModel):
    folder_id: NonEmptyString


class _RenameDirectoryRequest(RequestDataModel):
    folder_id: NonEmptyString
    new_name: NonEmptyString


class _MoveDirectoryRequest(RequestDataModel):
    folder_id: NonEmptyString
    target_folder_id: str | None


class _SetDirectoryRulesRequest(RequestDataModel):
    directory_id: NonEmptyString
    access_rules: _AccessRules
    inherit_parent: Omittable[bool] = REQUEST_UNSET


class _RestoreDirectoryRequest(RequestDataModel):
    folder_id: NonEmptyString
    target_parent_id: Omittable[NonEmptyString | None] = REQUEST_UNSET
    new_name: Omittable[NonEmptyString] = REQUEST_UNSET


class _ListDeletedItemsRequest(RequestDataModel):
    folder_id: NonEmptyString
    page_size: Omittable[PaginationPageSize] = REQUEST_UNSET
    cursor: PaginationCursorToken | None = None


def _mark_nodes_deleted(session, node_ids, operation_id: str) -> None:
    for chunk in batched(list(node_ids), QUERY_CHUNK_SIZE):
        session.query(Node).filter(Node.id.in_(list(chunk))).update(
            {
                Node.status: EntityStatus.DELETED,
                Node.status_operation_id: operation_id,
            },
            synchronize_session=False,
        )


def _evaluate_directory_read_access(
    session,
    user: User,
    directory: Folder,
    *,
    super_bypasses_target: bool,
    preload_all_rule_types: bool = False,
) -> tuple[bool, str | None, FolderAccessEvaluationContext | None]:
    has_super_access = Permissions.SUPER_LIST_DIRECTORY in user.all_permissions
    if has_super_access and super_bypasses_target:
        return True, directory.parent_id, None

    context = load_folder_access_evaluation_context(
        session,
        [directory],
        user,
        "read",
        preload_all_rule_types=preload_all_rule_types,
    )
    if not context.allows(directory):
        return False, None, context

    parent = (
        None
        if directory.parent_id is None
        else context.folder_map.get(directory.parent_id)
    )
    visible_parent_id = (
        directory.parent_id
        if parent is not None and (has_super_access or context.allows(parent))
        else None
    )
    return True, visible_parent_id, context


class RequestListDirectoryHandler(RequestHandler):
    """Handles directory listing requests.
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

    request_model = _ListDirectoryRequest

    require_auth = True
    rate_limit_cost = 3

    def handle(self, handler: ConnectionHandler):

        # Parse the directory listing request
        folder_id: str | None = handler.data.get("folder_id")
        page_size = get_page_size(handler.data)
        cursor = handler.data.get("cursor")

        with Session() as session:
            this_user = User.get_existing(session, handler.username)

            # Determine parent folder and fetch children/documents
            if not folder_id:
                folder_id = ROOT_DIRECTORY_ID

            folder = session.query(Folder).filter(Folder.id == folder_id).first()
            if not folder:
                handler.conclude_request(404, {}, smsg.DIRECTORY_NOT_FOUND)
                return Result(code=404, target=folder_id, username=handler.username)

            has_permission, parent_id, _ = _evaluate_directory_read_access(
                session,
                this_user,
                folder,
                super_bypasses_target=True,
            )

            if not has_permission:
                handler.conclude_access_denial()
                return Result(code=403, target=folder_id, username=handler.username)

            filters = {"folder_id": folder_id}
            sort = "type_name_id:asc"
            try:
                decoded_cursor = PaginationCursor.decode(
                    cursor,
                    action="list_directory",
                    sort=sort,
                    filters=filters,
                    value_types=[int, str, str],
                )
                last_key = None if decoded_cursor is None else decoded_cursor.last
            except CursorError as exc:
                handler.conclude_request(400, {}, str(exc))
                return Result(code=400, target=folder_id, username=handler.username)

            items = fetch_directory_listing_items(
                session,
                folder_id,
                last_key,
                page_size + 1,
            )

            data = make_cursor_response(
                items,
                page_size=page_size,
                action="list_directory",
                sort=sort,
                filters=filters,
                cursor_key=directory_cursor_key,
            )
            data["parent_id"] = parent_id
            response = {
                "code": 200,
                "message": "Directory listing successful",
                "data": data,
            }

        # Send the response back to the client
        handler.conclude_request(**response)
        return Result(code=200, target=folder_id, username=handler.username)


class RequestGetDirectoryInfoHandler(RequestHandler):
    """Handles directory information requests.
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

    request_model = _DirectoryIDRequest

    require_auth = True
    rate_limit_cost = 3

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
                return Result(code=404, target=directory_id, username=handler.username)

            can_view_access_rules = (
                Permissions.VIEW_ACCESS_RULES in user.all_permissions
            )
            has_permission, parent_id, access_context = _evaluate_directory_read_access(
                session,
                user,
                directory,
                super_bypasses_target=False,
                preload_all_rule_types=can_view_access_rules,
            )
            if not has_permission:
                handler.conclude_access_denial()
                return Result(code=403, target=directory_id, username=handler.username)

            info_code = 0
            access_rules = []
            if can_view_access_rules:
                assert access_context is not None
                access_rules = get_access_rules_list_from_map(
                    access_context.compiled_rules_by_target,
                    target_type="directory",
                    target_id=directory.id,
                )
            else:
                info_code = 1  # No permission to view directory access rules.

            data = {
                "directory_id": directory.id,
                "count_of_child": count_active_directory_children(
                    session, directory.id
                ),
                "parent_id": parent_id,
                "name": directory.name,
                "created_time": directory.created_time,
                "access_rules": access_rules,
                "info_code": info_code,
            }

            handler.conclude_request(200, data, "Directory info retrieved successfully")
            return Result(code=0, target=directory_id, username=handler.username)


class RequestGetDirectoryAccessRulesHandler(RequestHandler):
    request_model = _DirectoryIDRequest
    require_auth = True
    rate_limit_cost = 2

    def handle(self, handler: ConnectionHandler):

        directory_id: str = handler.data["directory_id"]

        with Session() as session:
            user = User.get_existing(session, handler.username)
            directory = session.get(Folder, directory_id)

            if not directory:
                handler.conclude_request(404, {}, smsg.DIRECTORY_NOT_FOUND)
                return Result(code=404, target=directory_id, username=handler.username)

            if (
                not check_access_requirements(
                    session, user, directory, access_type="read"
                )
                or Permissions.VIEW_ACCESS_RULES not in user.all_permissions
            ):
                handler.conclude_access_denial()
                return Result(code=403, target=directory_id, username=handler.username)

            handler.conclude_request(
                200,
                {
                    "rules": get_access_rules_dict(
                        session,
                        target_type="directory",
                        target_id=directory.id,
                    ),
                    "inherit": directory.inherit,
                },
                "Directory access rules retrieved successfully",
            )
            return Result(code=0, target=directory_id, username=handler.username)


class RequestCreateDirectoryHandler(RequestHandler):
    """Handles directory creation requests.
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

    request_model = _CreateDirectoryRequest

    require_auth = True
    rate_limit_cost = 3

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
                return Result(code=403, target=parent_id, username=handler.username)

            parent = session.get(Folder, parent_id)
            if not parent:
                handler.conclude_request(404, {}, smsg.DIRECTORY_NOT_FOUND)
                return Result(code=404, target=parent_id, username=handler.username)
            if not check_access_requirements(session, this_user, parent, "write"):
                if (
                    parent_id == ROOT_DIRECTORY_ID
                    and Permissions.SUPER_CREATE_DIRECTORY in this_user.all_permissions
                ):
                    # Allow super creation in root directory if global permission is given
                    pass
                else:
                    handler.conclude_access_denial()
                    return Result(code=403, target=parent_id, username=handler.username)

            folder = Folder(name=name, parent=parent)
            session.add(folder)
            try:
                with node_name_mutation(session, parent_id, name):
                    if not apply_access_rules(
                        folder, access_rules, this_user, inherit_parent
                    ):
                        session.rollback()
                        handler.conclude_access_denial()
                        return Result(
                            code=403,
                            target=parent_id,
                            username=handler.username,
                        )
                    session.commit()
            except NodeNameConflictError:
                payload, message = describe_node_name_conflict(
                    session, this_user, parent_id, name
                )
                existing_folder = payload.pop("entity", None)
                if exists_ok and existing_folder is not None:
                    handler.conclude_request(
                        200,
                        {
                            "id": existing_folder.id,
                            "name": existing_folder.name,
                            "last_modified": existing_folder.created_time,
                        },
                        "Directory already exists",
                    )
                    return Result(code=0, target=parent_id, username=handler.username)
                return respond_to_node_name_conflict(
                    handler,
                    payload,
                    message,
                    target=parent_id,
                    result_data={"name": name},
                )

            handler.conclude_request(
                200,
                {
                    "id": folder.id,
                    "name": folder.name,
                    "last_modified": folder.created_time,
                },
                "Directory created successfully",
            )
            return Result(code=0, target=parent_id, username=handler.username)


class RequestDeleteDirectoryHandler(RequestHandler):
    """Handles directory deletion requests.
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

    request_model = _FolderIDRequest

    require_auth = True
    rate_limit_cost = 10

    def handle(self, handler: ConnectionHandler):

        # Parse the directory deletion request
        folder_id = handler.data["folder_id"]  # Get the folder ID from the request data

        if folder_id == ROOT_DIRECTORY_ID:
            handler.conclude_request(404, {}, smsg.DIRECTORY_NOT_FOUND)
            return Result(code=404, target=folder_id, username=handler.username)

        cancelled_task_ids: list[str] = []
        with Session() as session:
            this_user = User.get_existing(session, handler.username)
            folder = session.get(Folder, folder_id)
            if not folder:
                handler.conclude_request(404, {}, smsg.DIRECTORY_NOT_FOUND)
                return Result(code=404, target=folder_id, username=handler.username)
            if (
                Permissions.DELETE_DIRECTORY not in this_user.all_permissions
                or not check_access_requirements(session, this_user, folder, "write")
            ):
                handler.conclude_access_denial()
                return Result(code=403, target=folder_id, username=handler.username)

            operation_id = f"OP_DEL_{secrets.token_hex(8)}_{int(time.time())}"
            now = time.time()

            # analyze subtree, determine deletable items and protected items,
            # prepare for batch deletion
            (
                deletable_folder_ids,
                deletable_doc_ids,
                failed_items,
                protected_folder_ids,
                _folder_map,
            ) = fetch_subtree_for_deletion(session, folder_id, this_user, now=now)

            # execute batch deletion in a transaction

            # 2a. Mark documents and folders as DELETED
            _mark_nodes_deleted(
                session,
                set(deletable_doc_ids) | set(deletable_folder_ids),
                operation_id,
            )
            unreachable_file_ids = find_unreachable_document_file_ids(
                session, list(deletable_doc_ids)
            )
            cancelled_task_ids = cancel_file_tasks_for_files(
                session, unreachable_file_ids
            )

            # 2b. Mark the root folder as DELETED
            root_fully_deletable = (
                len(protected_folder_ids) == 0 and len(failed_items) == 0
            )
            if root_fully_deletable:
                folder.status = EntityStatus.DELETED
                folder.status_operation_id = operation_id

            session.commit()
            publish_cancelled_file_tasks(cancelled_task_ids)

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
                return Result(code=207, target=folder_id, username=handler.username)
            else:
                handler.conclude_request(
                    200, {}, "Directory marked as deleted successfully"
                )
                return Result(code=0, target=folder_id, username=handler.username)


class RequestRenameDirectoryHandler(RequestHandler):
    """Handles directory renaming requests.
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

    request_model = _RenameDirectoryRequest

    require_auth = True
    rate_limit_cost = 3

    def handle(self, handler: ConnectionHandler):

        # Parse the directory renaming request
        folder_id = handler.data["folder_id"]
        new_name = handler.data["new_name"]

        if folder_id == ROOT_DIRECTORY_ID:
            handler.conclude_request(404, {}, smsg.DIRECTORY_NOT_FOUND)
            return Result(code=404, target=folder_id, username=handler.username)

        with Session() as session:
            this_user = User.get_existing(session, handler.username)

            folder = session.get(Folder, folder_id)
            if not folder:
                handler.conclude_request(404, {}, smsg.DIRECTORY_NOT_FOUND)
                return Result(code=404, target=folder_id, username=handler.username)

            if (
                Permissions.RENAME_DIRECTORY not in this_user.all_permissions
                or not check_access_requirements(session, this_user, folder, "write")
            ):
                handler.conclude_access_denial()
                return Result(code=403, target=folder_id, username=handler.username)

            if folder.name == new_name:
                handler.conclude_request(
                    code=400,
                    message="New name is the same as the current name",
                    data={},
                )
                return

            parent_id = folder.parent_id or ROOT_DIRECTORY_ID
            try:
                with node_name_mutation(session, parent_id, new_name):
                    folder.name = new_name
                    session.commit()
            except NodeNameConflictError:
                payload, message = describe_node_name_conflict(
                    session, this_user, parent_id, new_name
                )
                return respond_to_node_name_conflict(
                    handler,
                    payload,
                    message,
                    target=folder_id,
                    result_data={"title": new_name},
                )

            handler.conclude_request(
                code=200, message="Directory renamed successfully", data={}
            )
            return Result(code=0, target=folder_id, username=handler.username)


class RequestMoveDirectoryHandler(RequestHandler):
    request_model = _MoveDirectoryRequest

    require_auth = True
    rate_limit_cost = 3

    def handle(self, handler: ConnectionHandler):

        folder_id: str = handler.data["folder_id"]
        target_folder_id: str | None = handler.data.get("target_folder_id")

        if not target_folder_id:
            target_folder_id = ROOT_DIRECTORY_ID

        if folder_id == ROOT_DIRECTORY_ID:
            handler.conclude_request(404, {}, smsg.DIRECTORY_NOT_FOUND)
            return Result(code=404, target=folder_id, username=handler.username)

        with Session() as session:
            user = User.get_existing(session, handler.username)

            if Permissions.MOVE not in user.all_permissions:
                handler.conclude_request(403, {}, smsg.ACCESS_DENIED_MOVE_DIRECTORY)
                return Result(code=403, target=folder_id, username=handler.username)

            folder = session.get(Folder, folder_id)

            if not folder:
                handler.conclude_request(
                    code=404, message=smsg.SUBJECT_DIRECTORY_NOT_FOUND, data={}
                )
                return Result(code=404, target=folder_id, username=handler.username)

            if not check_access_requirements(session, user, folder, "move"):
                handler.conclude_request(403, {}, smsg.ACCESS_DENIED_MOVE_DIRECTORY)
                return Result(code=403, target=folder_id, username=handler.username)

            target_folder = session.get(Folder, target_folder_id)
            if not target_folder:
                handler.conclude_request(
                    code=404, message=smsg.TARGET_DIRECTORY_NOT_FOUND, data={}
                )
                return Result(code=404, target=folder_id, username=handler.username)

            if not check_access_requirements(session, user, target_folder, "write"):
                if (
                    target_folder_id == ROOT_DIRECTORY_ID
                    and Permissions.SUPER_CREATE_DIRECTORY in user.all_permissions
                ):
                    pass
                else:
                    handler.conclude_request(
                        403, {}, smsg.ACCESS_DENIED_WRITE_DIRECTORY
                    )
                    return Result(code=403, target=folder_id, username=handler.username)

            # Check if target folder is a descendant of the folder being moved
            if target_folder.id == folder.id or target_folder.is_descendant_of(folder):
                handler.conclude_request(
                    400, {}, smsg.CANNOT_MOVE_DIRECTORY_INTO_SUBDIRECTORY
                )
                return Result(code=400, target=folder_id, username=handler.username)

            name = folder.name
            try:
                with node_name_mutation(session, target_folder_id, name):
                    folder.parent = target_folder
                    session.commit()
            except NodeNameConflictError:
                payload, message = describe_node_name_conflict(
                    session, user, target_folder_id, name
                )
                return respond_to_node_name_conflict(
                    handler,
                    payload,
                    message,
                    target=folder_id,
                    result_data={"title": name},
                )

        handler.conclude_request(200, {}, smsg.SUCCESS)
        return Result(code=0, target=folder_id, username=handler.username)


class RequestSetDirectoryRulesHandler(RequestHandler):
    """Handles the "set_directory_rules" action."""

    request_model = _SetDirectoryRulesRequest

    require_auth = True
    rate_limit_cost = 5

    def handle(self, handler: ConnectionHandler):
        """Handles the directory access rules setting request from the client."""
        directory_id: str = handler.data["directory_id"]
        access_rules_to_apply: dict = handler.data["access_rules"]
        inherit_parent: bool = handler.data.get("inherit_parent", True)

        if not handler.username:
            handler.conclude_request(401, {}, smsg.AUTHENTICATION_REQUIRED)
            return Result(code=401, target=directory_id)

        with Session() as session:
            user = User.get_existing(session, handler.username)

            directory = session.get(Folder, directory_id)

            if not directory:
                handler.conclude_request(404, {}, smsg.DIRECTORY_NOT_FOUND)
                return Result(code=404, target=directory_id, username=handler.username)

            if Permissions.SET_ACCESS_RULES not in user.all_permissions:
                handler.conclude_request(403, {}, smsg.ACCESS_DENIED_SET_ACCESS_RULES)
                return Result(code=403, target=directory_id, username=handler.username)

            if not check_access_requirements(
                session, user, directory, access_type="manage"
            ):
                handler.conclude_access_denial()
                return Result(code=403, target=directory_id, username=handler.username)

            try:
                if apply_access_rules(
                    directory, access_rules_to_apply, user, inherit_parent
                ):
                    session.commit()
                    handler.conclude_request(200, {}, "Set access rules successfully")
                    return Result(
                        code=0, target=directory_id, username=handler.username
                    )
                else:
                    session.rollback()
                    handler.conclude_access_denial()
                    return Result(
                        code=403, target=directory_id, username=handler.username
                    )
            except (ValueError, jsonschema.ValidationError) as exc:
                session.rollback()
                handler.conclude_request(400, {}, f"Set access rules failed: {exc!s}")
                return Result(code=400, target=directory_id, username=handler.username)


class RequestPurgeDirectoryHandler(RequestHandler):
    """Handles the "purge_directory" action.
    Permanently removes a directory, all its subdirectories, and all documents within.
    This action is irreversible.
    """

    request_model = _FolderIDRequest

    require_auth = True
    rate_limit_cost = 20

    def handle(self, handler: ConnectionHandler):
        folder_id = handler.data["folder_id"]

        if folder_id == ROOT_DIRECTORY_ID:
            handler.conclude_request(403, {}, smsg.CANNOT_PURGE_ROOT_DIRECTORY)
            return Result(code=403, target=folder_id, username=handler.username)

        with Session() as session:
            user = User.get_existing(session, handler.username)

            if Permissions.PURGE not in user.all_permissions:
                handler.conclude_permission_denial()
                return Result(code=403, target=folder_id, username=handler.username)

            folder = session.get(
                Folder, folder_id, execution_options={"include_deleted": True}
            )

            if not folder:
                handler.conclude_request(404, {}, smsg.DIRECTORY_NOT_FOUND)
                return Result(code=404, target=folder_id, username=handler.username)

            if folder.status != EntityStatus.DELETED:
                handler.conclude_request(
                    400, {}, "Directory must be marked as deleted before purging"
                )
                return Result(code=400, target=folder_id, username=handler.username)

            if not check_access_requirements(session, user, folder, "write"):
                handler.conclude_access_denial()
                return Result(code=403, target=folder_id, username=handler.username)

            try:
                (
                    all_folder_ids,
                    all_doc_ids,
                    failed_items,
                    _,
                    _folder_map,
                ) = fetch_subtree_for_deletion(
                    session, folder_id, user, include_deleted=True
                )

                if failed_items:
                    handler.conclude_request(
                        403,
                        {"failed": failed_items},
                        "Some items in the directory cannot be purged due to insufficient permissions",
                    )
                    return Result(code=403, target=folder_id, username=handler.username)

                session.autoflush = False

                if all_doc_ids:
                    purge_documents_bulk(session, list(all_doc_ids))

                delete_compiled_access_rules_for_targets(
                    session,
                    (
                        ("directory", target_id)
                        for target_id in [*all_folder_ids, folder_id]
                    ),
                )

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
                return Result(code=0, target=folder_id, username=handler.username)

            finally:
                session.autoflush = True


class RequestRestoreDirectoryHandler(RequestHandler):
    """Handles the "restore_directory" action.
    Supports virtual ROOT_DIRECTORY_ID translation to database None.
    """

    request_model = _RestoreDirectoryRequest

    require_auth = True
    rate_limit_cost = 10

    def handle(self, handler: ConnectionHandler):
        folder_id = handler.data["folder_id"]
        target_parent_provided = "target_parent_id" in handler.data
        target_parent_id = handler.data.get("target_parent_id")
        new_name = handler.data.get("new_name")

        if folder_id == ROOT_DIRECTORY_ID:
            handler.conclude_request(400, {}, smsg.CANNOT_RESTORE_ROOT_DIRECTORY)
            return Result(code=400, target=folder_id, username=handler.username)

        with Session() as session:
            user = User.get_existing(session, handler.username)

            if Permissions.RESTORE not in user.all_permissions:
                handler.conclude_permission_denial()
                return Result(code=403, target=folder_id, username=handler.username)

            folder = session.get(
                Folder, folder_id, execution_options={"include_deleted": True}
            )

            if not folder or folder.status != EntityStatus.DELETED:
                handler.conclude_request(404, {}, smsg.DELETED_DIRECTORY_NOT_FOUND)
                return Result(code=404, target=folder_id, username=handler.username)

            if not check_access_requirements(session, user, folder, "write"):
                handler.conclude_access_denial()
                return Result(code=403, target=folder_id, username=handler.username)

            if target_parent_provided:
                db_parent_id = target_parent_id or ROOT_DIRECTORY_ID
            else:
                db_parent_id = folder.parent_id or ROOT_DIRECTORY_ID

            final_name = new_name if new_name else folder.name

            target_parent = (
                session.query(Folder)
                .execution_options(include_deleted=True)
                .filter_by(id=db_parent_id)
                .first()
            )
            if not target_parent or target_parent.status != EntityStatus.OK:
                handler.conclude_request(409, {}, smsg.TARGET_DIRECTORY_NOT_ACTIVE)
                return Result(code=409, target=db_parent_id, username=handler.username)

            if not check_access_requirements(session, user, target_parent, "write"):
                handler.conclude_access_denial()
                return Result(code=403, target=db_parent_id, username=handler.username)

            op_id = folder.status_operation_id
            try:
                with node_name_mutation(session, db_parent_id, final_name):
                    if op_id:
                        session.query(Node).filter(
                            Node.status_operation_id == op_id,
                            Node.status == EntityStatus.DELETED,
                        ).update(
                            {
                                Node.status: EntityStatus.OK,
                                Node.status_operation_id: None,
                            },
                            synchronize_session=False,
                        )

                    folder.status = EntityStatus.OK
                    folder.status_operation_id = None
                    folder.name = final_name
                    folder.parent_id = db_parent_id
                    session.commit()
            except NodeNameConflictError:
                payload, message = describe_subtree_restore_name_conflict(
                    session,
                    user,
                    op_id,
                    db_parent_id,
                    final_name,
                )
                return respond_to_node_name_conflict(
                    handler,
                    payload,
                    message,
                    target=folder_id,
                    result_data={},
                )

            handler.conclude_request(
                200, {"parent_id": db_parent_id, "name": final_name}, smsg.SUCCESS
            )
            return Result(code=0, target=folder_id, username=handler.username)


class RequestListDeletedItemsHandler(RequestHandler):
    """Handles the "list_deleted_items" action.
    Lists folders and documents that have been marked as deleted within
     a specific parent directory.
    """

    request_model = _ListDeletedItemsRequest

    require_auth = True
    rate_limit_cost = 3

    def handle(self, handler: ConnectionHandler):
        parent_id = handler.data["folder_id"]
        page_size = get_page_size(handler.data)
        cursor = handler.data.get("cursor")

        with Session() as session:
            user = User.get_existing(session, handler.username)

            if Permissions.LIST_DELETED_ITEMS not in user.all_permissions:
                handler.conclude_permission_denial()
                return Result(code=403, target=parent_id, username=handler.username)

            db_parent_id = parent_id

            parent_folder = session.get(
                Folder,
                db_parent_id,
                execution_options={"include_deleted": True},
            )

            if not parent_folder:
                handler.conclude_request(404, {}, smsg.DIRECTORY_NOT_FOUND)
                return Result(code=404, target=parent_id, username=handler.username)

            if (
                Permissions.SUPER_LIST_DIRECTORY not in user.all_permissions
                and not check_access_requirements(session, user, parent_folder, "read")
            ):
                handler.conclude_access_denial()
                return Result(code=403, target=parent_id, username=handler.username)

            filters = {"folder_id": db_parent_id}
            sort = "type_name_id:asc"
            try:
                decoded_cursor = PaginationCursor.decode(
                    cursor,
                    action="list_deleted_items",
                    sort=sort,
                    filters=filters,
                    value_types=[int, str, str],
                )
                last_key = None if decoded_cursor is None else decoded_cursor.last
            except CursorError as exc:
                handler.conclude_request(400, {}, str(exc))
                return Result(code=400, target=parent_id, username=handler.username)

            items = fetch_deleted_listing_items(
                session,
                db_parent_id,
                last_key,
                page_size + 1,
            )

            result_data = make_cursor_response(
                items,
                page_size=page_size,
                action="list_deleted_items",
                sort=sort,
                filters=filters,
                cursor_key=directory_cursor_key,
            )
            result_data["parent_id"] = parent_id

            handler.conclude_request(200, result_data, "Deleted items retrieved")
            return Result(code=0, target=parent_id, username=handler.username)

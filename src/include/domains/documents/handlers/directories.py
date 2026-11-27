import secrets
import time
from itertools import batched

from cacl_compiler import AtomicOp, ObjectType
from sqlalchemy import select

from include.config.constants import (
    QUERY_CHUNK_SIZE,
    ROOT_DIRECTORY_ID,
)
from include.database.models.documents import (
    EntityStatus,
    Folder,
    Node,
)
from include.database.models.identity import User
from include.database.session import Session
from include.domains.access.authorization.engine import ObjectState
from include.domains.access.authorization.evaluation import (
    authorize_create_on_parent,
    authorize_directory_access,
    authorize_directory_reparent,
    authorize_node_operation,
    authorize_purge_descendants,
    authorize_restore_descendants,
    authorize_soft_delete_descendants,
    check_directory_purge_root,
    check_directory_restore_root,
    check_directory_soft_delete_root,
    compute_created_node_effective_mask,
    global_gate_ops_mask,
    project_effective_mask,
)
from include.domains.access.authorization.storage import (
    delete_node_dacl_rules_for_targets,
    persist_node_policy,
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
from include.domains.documents.handlers.dacl import (
    DaclSource,
    NodeDaclTargetSpec,
    handle_get_node_dacl,
    handle_set_node_dacl,
    prepare_initial_node_dacl,
)
from include.domains.documents.handlers.name_conflict_responses import (
    respond_to_node_name_conflict,
)
from include.domains.documents.queries.deletion_tree import (
    fetch_subtree_ids_for_soft_delete,
    fetch_subtree_metadata_for_purge,
    fetch_subtree_metadata_for_restore,
    fetch_subtree_metadata_for_soft_delete,
)
from include.domains.documents.queries.file_references import (
    find_unreachable_document_file_ids,
)
from include.domains.documents.queries.listing import (
    attach_listing_effective_masks,
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
from include.transport.request_handler import (
    REQUEST_UNSET,
    Omittable,
    RequestDataModel,
    RequestHandler,
    Result,
)
lazy from include.types import NonEmptyString


class _ListDirectoryRequest(RequestDataModel):
    folder_id: str | None
    page_size: Omittable[PaginationPageSize] = REQUEST_UNSET
    cursor: PaginationCursorToken | None = None


class _DirectoryIDRequest(RequestDataModel):
    directory_id: NonEmptyString


class _GetDirectoryDaclRequest(RequestDataModel):
    directory_id: NonEmptyString
    annotate_users: Omittable[bool] = REQUEST_UNSET


class _SetDirectoryDaclRequest(RequestDataModel):
    directory_id: NonEmptyString
    dacl: DaclSource
    allow_self_lockout: Omittable[bool] = REQUEST_UNSET


class _CreateDirectoryRequest(RequestDataModel):
    parent_id: str | None = None
    name: NonEmptyString
    dacl: Omittable[DaclSource] = REQUEST_UNSET
    allow_self_lockout: Omittable[bool] = REQUEST_UNSET
    exists_ok: Omittable[bool] = REQUEST_UNSET


class _FolderIDRequest(RequestDataModel):
    folder_id: NonEmptyString


class _RenameDirectoryRequest(RequestDataModel):
    folder_id: NonEmptyString
    new_name: NonEmptyString


class _ReparentDirectoryRequest(RequestDataModel):
    folder_id: NonEmptyString
    target_folder_id: str | None


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


class RequestListDirectoryHandler(RequestHandler[_ListDirectoryRequest]):
    request_model = _ListDirectoryRequest

    requires_auth = True
    rate_limit_cost = 3

    def handle(self, handler, request):
        folder_id: str | None = request.folder_id
        page_size = get_page_size(request.model_dump(mode="json", exclude_unset=True))
        cursor = request.cursor

        with Session() as session:
            this_user = User.get_existing(session, handler.user_id)

            if not folder_id:
                folder_id = ROOT_DIRECTORY_ID

            folder = session.query(Folder).filter(Folder.id == folder_id).first()
            if not folder:
                handler.conclude_request(404, {}, smsg.DIRECTORY_NOT_FOUND)
                return Result(code=404, target=folder_id, user_id=handler.user_id)

            access = authorize_directory_access(
                session,
                this_user,
                folder,
                AtomicOp.LIST_DIRECTORY,
                include_visible_parent=True,
            )
            if not access.allowed:
                handler.conclude_access_denial()
                return Result(code=403, target=folder_id, user_id=handler.user_id)

            filters = {"folder_id": folder_id}
            sort = "type_name_id:asc"
            try:
                decoded_cursor = PaginationCursor.decode(
                    cursor,
                    action="core.directory.list",
                    sort=sort,
                    filters=filters,
                    value_types=[int, str, str],
                )
                last_key = None if decoded_cursor is None else decoded_cursor.last
            except CursorError as exc:
                handler.conclude_request(400, {}, str(exc))
                return Result(code=400, target=folder_id, user_id=handler.user_id)

            items = fetch_directory_listing_items(
                session,
                folder_id,
                last_key,
                page_size + 1,
                include_inherit_meta=True,
            )
            inherit_by_id = {
                item["id"]: item["_node_inherit"] for item in items[:page_size]
            }

            data = make_cursor_response(
                items,
                page_size=page_size,
                action="core.directory.list",
                sort=sort,
                filters=filters,
                cursor_key=directory_cursor_key,
            )
            attach_listing_effective_masks(
                session,
                this_user,
                access,
                data["items"],
                inherit_by_id=inherit_by_id,
                state=ObjectState.NORMAL,
            )
            data["parent_id"] = access.visible_parent_id
            data["effective_mask"] = access.effective_mask
            response = {
                "code": 200,
                "message": "Directory listing successful",
                "data": data,
            }

        handler.conclude_request(**response)
        return Result(code=200, target=folder_id, user_id=handler.user_id)


class RequestGetDirectoryInfoHandler(RequestHandler[_DirectoryIDRequest]):
    request_model = _DirectoryIDRequest

    requires_auth = True
    rate_limit_cost = 3

    def handle(self, handler, request):
        directory_id: str = request.directory_id

        with Session() as session:
            user = User.get_existing(session, handler.user_id)
            directory = session.get(Folder, directory_id)

            if not directory:
                handler.conclude_request(404, {}, smsg.DIRECTORY_NOT_FOUND)
                return Result(code=404, target=directory_id, user_id=handler.user_id)

            access = authorize_directory_access(
                session,
                user,
                directory,
                AtomicOp.READ_METADATA,
                include_visible_parent=True,
            )
            if not access.allowed:
                handler.conclude_access_denial()
                return Result(code=403, target=directory_id, user_id=handler.user_id)

            data = {
                "directory_id": directory.id,
                "count_of_child": count_active_directory_children(
                    session, directory.id
                ),
                "parent_id": access.visible_parent_id,
                "name": directory.name,
                "created_time": directory.created_time,
                "effective_mask": access.effective_mask,
            }

            handler.conclude_request(200, data, "Directory info retrieved successfully")
            return Result(code=0, target=directory_id, user_id=handler.user_id)


_DIRECTORY_DACL_TARGET = NodeDaclTargetSpec(
    model_cls=Folder,
    target_type=ObjectType.DIRECTORY,
    not_found_message=smsg.DIRECTORY_NOT_FOUND,
    get_success_message="Directory DACL retrieved successfully",
    set_success_message="Directory DACL updated successfully",
)


class RequestGetDirectoryDaclHandler(RequestHandler[_GetDirectoryDaclRequest]):
    """Handles the "core.directory.dacl.get" action."""

    request_model = _GetDirectoryDaclRequest
    requires_auth = True
    rate_limit_cost = 2

    def handle(self, handler, request):
        annotate_users: bool = (
            request.annotate_users
            if request.annotate_users is not REQUEST_UNSET
            else False
        )

        with Session() as session:
            return handle_get_node_dacl(
                session,
                handler,
                spec=_DIRECTORY_DACL_TARGET,
                target_id=request.directory_id,
                annotate_users=annotate_users,
            )


class RequestSetDirectoryDaclHandler(RequestHandler[_SetDirectoryDaclRequest]):
    """Handles the "core.directory.dacl.set" action."""

    request_model = _SetDirectoryDaclRequest
    requires_auth = True
    rate_limit_cost = 5

    def handle(self, handler, request):
        allow_self_lockout: bool = (
            request.allow_self_lockout
            if request.allow_self_lockout is not REQUEST_UNSET
            else False
        )

        with Session() as session:
            return handle_set_node_dacl(
                session,
                handler,
                spec=_DIRECTORY_DACL_TARGET,
                target_id=request.directory_id,
                dacl_source=request.dacl,
                allow_self_lockout=allow_self_lockout,
            )


class RequestCreateDirectoryHandler(RequestHandler[_CreateDirectoryRequest]):
    request_model = _CreateDirectoryRequest

    requires_auth = True
    rate_limit_cost = 3

    def handle(self, handler, request):
        parent_id = request.parent_id or ROOT_DIRECTORY_ID
        name = request.name
        exists_ok = (
            request.exists_ok if request.exists_ok is not REQUEST_UNSET else False
        )
        dacl_source = request.dacl if request.dacl is not REQUEST_UNSET else None
        allow_self_lockout = (
            request.allow_self_lockout
            if request.allow_self_lockout is not REQUEST_UNSET
            else False
        )

        with Session() as session:
            this_user = User.get_existing(session, handler.user_id)

            parent = session.get(Folder, parent_id)
            if not parent:
                handler.conclude_request(404, {}, smsg.DIRECTORY_NOT_FOUND)
                return Result(code=404, target=parent_id, user_id=handler.user_id)

            create_check = authorize_create_on_parent(
                session,
                this_user,
                parent,
                AtomicOp.CREATE_DIRECTORY,
                require_write_dacl=dacl_source is not None,
            )
            if not create_check.can_create:
                handler.conclude_access_denial()
                return Result(code=403, target=parent_id, user_id=handler.user_id)

            compiled_policy, dacl_error = prepare_initial_node_dacl(
                session,
                this_user,
                parent,
                object_type=ObjectType.DIRECTORY,
                name=name,
                dacl_source=dacl_source,
                create_check=create_check,
                allow_self_lockout=allow_self_lockout,
            )
            if dacl_error is not None:
                code, error_data, message = dacl_error
                handler.conclude_request(code, error_data, message)
                return Result(code=code, target=parent_id, user_id=handler.user_id)

            folder = Folder(name=name, parent=parent)
            session.add(folder)
            try:
                with node_name_mutation(session, parent_id, name):
                    session.flush()
                    if compiled_policy is not None:
                        persist_node_policy(session, folder, compiled_policy)
                    session.commit()
            except NodeNameConflictError:
                payload, message = describe_node_name_conflict(
                    session, this_user, parent_id, name
                )
                existing_folder = payload.pop("entity", None)
                raw_effective_mask = payload.pop("raw_effective_mask", 0)
                if exists_ok and existing_folder is not None:
                    existing_mask = project_effective_mask(
                        raw_effective_mask,
                        object_type=ObjectType.DIRECTORY,
                        state=ObjectState.NORMAL,
                        global_mask=global_gate_ops_mask(this_user),
                        is_root=(existing_folder.id == ROOT_DIRECTORY_ID),
                    )
                    handler.conclude_request(
                        200,
                        {
                            "id": existing_folder.id,
                            "name": existing_folder.name,
                            "last_modified": existing_folder.created_time,
                            "effective_mask": existing_mask,
                        },
                        "Directory already exists",
                    )
                    return Result(code=0, target=parent_id, user_id=handler.user_id)
                return respond_to_node_name_conflict(
                    handler,
                    payload,
                    message,
                    target=parent_id,
                    result_data={"name": name},
                )

            effective_mask = compute_created_node_effective_mask(
                this_user,
                node_id=folder.id,
                name=folder.name,
                object_type=ObjectType.DIRECTORY,
                create_check=create_check,
                initial_policy=compiled_policy,
            )
            handler.conclude_request(
                200,
                {
                    "id": folder.id,
                    "name": folder.name,
                    "last_modified": folder.created_time,
                    "effective_mask": effective_mask,
                },
                "Directory created successfully",
            )
            return Result(code=0, target=parent_id, user_id=handler.user_id)


class RequestDeleteDirectoryHandler(RequestHandler[_FolderIDRequest]):
    request_model = _FolderIDRequest

    requires_auth = True
    rate_limit_cost = 10

    def handle(self, handler, request):
        folder_id = request.folder_id

        if folder_id == ROOT_DIRECTORY_ID:
            handler.conclude_request(404, {}, smsg.DIRECTORY_NOT_FOUND)
            return Result(code=404, target=folder_id, user_id=handler.user_id)

        cancelled_task_ids: list[str] = []
        with Session() as session:
            this_user = User.get_existing(session, handler.user_id)
            folder = session.get(
                Folder,
                folder_id,
                with_for_update=True,
                populate_existing=True,
            )
            if not folder:
                handler.conclude_request(404, {}, smsg.DIRECTORY_NOT_FOUND)
                return Result(code=404, target=folder_id, user_id=handler.user_id)

            root_check = check_directory_soft_delete_root(session, this_user, folder)
            if not root_check.allowed:
                handler.conclude_access_denial()
                return Result(code=403, target=folder_id, user_id=handler.user_id)

            if root_check.needs_descendant_check:
                descendant_folders, descendant_docs = (
                    fetch_subtree_metadata_for_soft_delete(session, folder_id)
                )
                decision = authorize_soft_delete_descendants(
                    session,
                    this_user,
                    folder.id,
                    [*descendant_folders, *descendant_docs],
                    root_check,
                )
                if not decision.allowed:
                    handler.conclude_access_denial()
                    return Result(code=403, target=folder_id, user_id=handler.user_id)
                descendant_folder_ids = [f.id for f in descendant_folders]
                descendant_doc_ids = [doc.id for doc in descendant_docs]
            else:
                descendant_folder_ids, descendant_doc_ids = (
                    fetch_subtree_ids_for_soft_delete(session, folder_id)
                )

            operation_id = f"OP_DEL_{secrets.token_hex(8)}_{int(time.time())}"
            all_node_ids = {
                folder.id,
                *descendant_folder_ids,
                *descendant_doc_ids,
            }
            _mark_nodes_deleted(session, all_node_ids, operation_id)

            if descendant_doc_ids:
                unreachable_file_ids = find_unreachable_document_file_ids(
                    session, descendant_doc_ids
                )
                cancelled_task_ids = cancel_file_tasks_for_files(
                    session, unreachable_file_ids
                )

            session.commit()
            publish_cancelled_file_tasks(cancelled_task_ids)

            handler.conclude_request(
                200, {}, "Directory marked as deleted successfully"
            )
            return Result(code=0, target=folder_id, user_id=handler.user_id)


class RequestRenameDirectoryHandler(RequestHandler[_RenameDirectoryRequest]):
    request_model = _RenameDirectoryRequest

    requires_auth = True
    rate_limit_cost = 3

    def handle(self, handler, request):
        folder_id = request.folder_id
        new_name = request.new_name

        if folder_id == ROOT_DIRECTORY_ID:
            handler.conclude_request(404, {}, smsg.DIRECTORY_NOT_FOUND)
            return Result(code=404, target=folder_id, user_id=handler.user_id)

        with Session() as session:
            this_user = User.get_existing(session, handler.user_id)

            folder = session.get(Folder, folder_id)
            if not folder:
                handler.conclude_request(404, {}, smsg.DIRECTORY_NOT_FOUND)
                return Result(code=404, target=folder_id, user_id=handler.user_id)

            if not authorize_node_operation(
                session, this_user, folder, AtomicOp.RENAME
            ).allowed:
                handler.conclude_access_denial()
                return Result(code=403, target=folder_id, user_id=handler.user_id)

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
            return Result(code=0, target=folder_id, user_id=handler.user_id)


class RequestReparentDirectoryHandler(RequestHandler[_ReparentDirectoryRequest]):
    """Handles the "core.directory.reparent" action."""

    request_model = _ReparentDirectoryRequest

    requires_auth = True
    rate_limit_cost = 3

    def handle(self, handler, request):
        folder_id: str = request.folder_id
        target_folder_id: str = request.target_folder_id or ROOT_DIRECTORY_ID

        if folder_id == ROOT_DIRECTORY_ID:
            handler.conclude_request(404, {}, smsg.DIRECTORY_NOT_FOUND)
            return Result(code=404, target=folder_id, user_id=handler.user_id)

        with Session() as session:
            user = User.get_existing(session, handler.user_id)
            locked_ids = (
                (folder_id,)
                if folder_id == target_folder_id
                else tuple(sorted((folder_id, target_folder_id)))
            )
            locked_folders = {
                row.id: row
                for row in session.scalars(
                    select(Folder)
                    .where(Folder.id.in_(locked_ids))
                    .order_by(Folder.id.asc())
                    .with_for_update()
                    .execution_options(populate_existing=True)
                ).all()
            }
            folder = locked_folders.get(folder_id)

            if not folder:
                handler.conclude_request(
                    code=404, message=smsg.SUBJECT_DIRECTORY_NOT_FOUND, data={}
                )
                return Result(code=404, target=folder_id, user_id=handler.user_id)

            target_folder = locked_folders.get(target_folder_id)
            if not target_folder:
                handler.conclude_request(
                    code=404, message=smsg.TARGET_DIRECTORY_NOT_FOUND, data={}
                )
                return Result(code=404, target=folder_id, user_id=handler.user_id)

            decision, dest_ancestor_ids = authorize_directory_reparent(
                session, user, folder, target_folder
            )
            if not decision.allowed:
                handler.conclude_request(403, {}, smsg.ACCESS_DENIED_REPARENT_DIRECTORY)
                return Result(code=403, target=folder_id, user_id=handler.user_id)

            if (folder.parent_id or ROOT_DIRECTORY_ID) == target_folder_id:
                handler.conclude_request(400, {}, smsg.CANNOT_REPARENT_TO_SAME_FOLDER)
                return Result(code=400, target=folder_id, user_id=handler.user_id)

            if target_folder.id == folder.id or folder.id in dest_ancestor_ids:
                handler.conclude_request(
                    400, {}, smsg.CANNOT_REPARENT_DIRECTORY_INTO_SUBDIRECTORY
                )
                return Result(code=400, target=folder_id, user_id=handler.user_id)

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
        return Result(code=0, target=folder_id, user_id=handler.user_id)


class RequestPurgeDirectoryHandler(RequestHandler[_FolderIDRequest]):
    request_model = _FolderIDRequest

    requires_auth = True
    rate_limit_cost = 20

    def handle(self, handler, request):
        folder_id = request.folder_id

        if folder_id == ROOT_DIRECTORY_ID:
            handler.conclude_request(403, {}, smsg.CANNOT_PURGE_ROOT_DIRECTORY)
            return Result(code=403, target=folder_id, user_id=handler.user_id)

        with Session() as session:
            user = User.get_existing(session, handler.user_id)

            if Permissions.PURGE not in user.all_permissions:
                handler.conclude_permission_denial()
                return Result(code=403, target=folder_id, user_id=handler.user_id)

            folder = session.get(
                Folder,
                folder_id,
                execution_options={"include_deleted": True},
                with_for_update=True,
                populate_existing=True,
            )
            if not folder:
                handler.conclude_request(404, {}, smsg.DIRECTORY_NOT_FOUND)
                return Result(code=404, target=folder_id, user_id=handler.user_id)

            if folder.status != EntityStatus.DELETED:
                handler.conclude_request(
                    400, {}, "Directory must be marked as deleted before purging"
                )
                return Result(code=400, target=folder_id, user_id=handler.user_id)

            root_check = check_directory_purge_root(session, user, folder)
            if not root_check.allowed:
                handler.conclude_access_denial()
                return Result(code=403, target=folder_id, user_id=handler.user_id)

            try:
                descendant_folders, descendant_docs = fetch_subtree_metadata_for_purge(
                    session, folder_id
                )
                descendant_decision = authorize_purge_descendants(
                    session,
                    user,
                    folder.id,
                    [*descendant_folders, *descendant_docs],
                    root_check,
                )
                if not descendant_decision.allowed:
                    handler.conclude_access_denial()
                    return Result(code=403, target=folder_id, user_id=handler.user_id)

                all_folder_ids = [f.id for f in descendant_folders]
                all_doc_ids = [doc.id for doc in descendant_docs]

                session.autoflush = False

                if all_doc_ids:
                    purge_documents_bulk(session, list(all_doc_ids))

                delete_node_dacl_rules_for_targets(
                    session, [*all_folder_ids, folder_id]
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
                return Result(code=0, target=folder_id, user_id=handler.user_id)

            finally:
                session.autoflush = True


class RequestRestoreDirectoryHandler(RequestHandler[_RestoreDirectoryRequest]):
    request_model = _RestoreDirectoryRequest

    requires_auth = True
    rate_limit_cost = 10

    def handle(self, handler, request):
        folder_id = request.folder_id
        target_parent_provided = "target_parent_id" in request.model_fields_set
        target_parent_id = (
            request.target_parent_id
            if request.target_parent_id is not REQUEST_UNSET
            else None
        )
        new_name = request.new_name if request.new_name is not REQUEST_UNSET else None

        if folder_id == ROOT_DIRECTORY_ID:
            handler.conclude_request(400, {}, smsg.CANNOT_RESTORE_ROOT_DIRECTORY)
            return Result(code=400, target=folder_id, user_id=handler.user_id)

        with Session() as session:
            user = User.get_existing(session, handler.user_id)

            folder = session.get(
                Folder,
                folder_id,
                execution_options={"include_deleted": True},
                with_for_update=True,
                populate_existing=True,
            )
            if not folder or folder.status != EntityStatus.DELETED:
                handler.conclude_request(404, {}, smsg.DELETED_DIRECTORY_NOT_FOUND)
                return Result(code=404, target=folder_id, user_id=handler.user_id)

            if target_parent_provided:
                db_parent_id = target_parent_id or ROOT_DIRECTORY_ID
            else:
                db_parent_id = folder.parent_id or ROOT_DIRECTORY_ID

            final_name = new_name if new_name else folder.name

            target_parent = (
                folder
                if db_parent_id == folder.id
                else session.query(Folder)
                .execution_options(include_deleted=True)
                .filter_by(id=db_parent_id)
                .with_for_update()
                .first()
            )
            if not target_parent or target_parent.status != EntityStatus.OK:
                handler.conclude_request(409, {}, smsg.TARGET_DIRECTORY_NOT_ACTIVE)
                return Result(code=409, target=db_parent_id, user_id=handler.user_id)

            root_check = check_directory_restore_root(
                session, user, folder, target_parent
            )
            if not root_check.allowed:
                handler.conclude_access_denial()
                return Result(code=403, target=folder_id, user_id=handler.user_id)

            if (
                target_parent.id == folder.id
                or folder.id in root_check.dest_ancestor_ids
            ):
                handler.conclude_request(
                    400, {}, smsg.CANNOT_REPARENT_DIRECTORY_INTO_SUBDIRECTORY
                )
                return Result(code=400, target=folder_id, user_id=handler.user_id)

            op_id = folder.status_operation_id
            descendant_restore_ids: list[str] = []
            if op_id:
                descendant_folders, descendant_docs = (
                    fetch_subtree_metadata_for_restore(session, folder_id, op_id)
                )
                descendant_rows = [*descendant_folders, *descendant_docs]
                descendant_decision = authorize_restore_descendants(
                    session, user, folder.id, descendant_rows, root_check
                )
                if not descendant_decision.allowed:
                    handler.conclude_access_denial()
                    return Result(code=403, target=folder_id, user_id=handler.user_id)
                descendant_restore_ids = [row.id for row in descendant_rows]

            try:
                with node_name_mutation(session, db_parent_id, final_name):
                    folder.status = EntityStatus.OK
                    folder.status_operation_id = None
                    folder.name = final_name
                    folder.parent_id = db_parent_id
                    session.flush()

                    for chunk in batched(descendant_restore_ids, QUERY_CHUNK_SIZE):
                        session.query(Node).filter(
                            Node.id.in_(list(chunk)),
                            Node.status == EntityStatus.DELETED,
                            Node.status_operation_id == op_id,
                        ).update(
                            {
                                Node.status: EntityStatus.OK,
                                Node.status_operation_id: None,
                            },
                            synchronize_session=False,
                        )
                    session.commit()
            except NodeNameConflictError:
                payload, message = describe_subtree_restore_name_conflict(
                    session,
                    user,
                    op_id,
                    db_parent_id,
                    final_name,
                    restoring_node_ids=descendant_restore_ids,
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
            return Result(code=0, target=folder_id, user_id=handler.user_id)


class RequestListDeletedItemsHandler(RequestHandler[_ListDeletedItemsRequest]):
    request_model = _ListDeletedItemsRequest

    requires_auth = True
    rate_limit_cost = 3

    def handle(self, handler, request):
        parent_id = request.folder_id
        page_size = get_page_size(request.model_dump(mode="json", exclude_unset=True))
        cursor = request.cursor

        with Session() as session:
            user = User.get_existing(session, handler.user_id)
            db_parent_id = parent_id

            parent_folder = session.get(
                Folder,
                db_parent_id,
                execution_options={"include_deleted": True},
            )
            if not parent_folder:
                handler.conclude_request(404, {}, smsg.DIRECTORY_NOT_FOUND)
                return Result(code=404, target=parent_id, user_id=handler.user_id)

            access = authorize_directory_access(
                session,
                user,
                parent_folder,
                AtomicOp.LIST_DELETED,
                include_visible_parent=False,
            )
            if not access.allowed:
                handler.conclude_access_denial()
                return Result(code=403, target=parent_id, user_id=handler.user_id)

            filters = {"folder_id": db_parent_id}
            sort = "type_name_id:asc"
            try:
                decoded_cursor = PaginationCursor.decode(
                    cursor,
                    action="core.directory.deleted_item.list",
                    sort=sort,
                    filters=filters,
                    value_types=[int, str, str],
                )
                last_key = None if decoded_cursor is None else decoded_cursor.last
            except CursorError as exc:
                handler.conclude_request(400, {}, str(exc))
                return Result(code=400, target=parent_id, user_id=handler.user_id)

            items = fetch_deleted_listing_items(
                session,
                db_parent_id,
                last_key,
                page_size + 1,
                include_inherit_meta=True,
            )
            inherit_by_id = {
                item["id"]: item["_node_inherit"] for item in items[:page_size]
            }

            result_data = make_cursor_response(
                items,
                page_size=page_size,
                action="core.directory.deleted_item.list",
                sort=sort,
                filters=filters,
                cursor_key=directory_cursor_key,
            )
            attach_listing_effective_masks(
                session,
                user,
                access,
                result_data["items"],
                inherit_by_id=inherit_by_id,
                state=ObjectState.SOFT_DELETED,
                include_deleted=True,
            )
            result_data["parent_id"] = parent_id
            result_data["effective_mask"] = access.effective_mask

            handler.conclude_request(200, result_data, "Deleted items retrieved")
            return Result(code=0, target=parent_id, user_id=handler.user_id)

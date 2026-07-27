from collections.abc import Iterator
from contextlib import contextmanager

from sqlalchemy.exc import IntegrityError
from sqlalchemy.orm import Session

from include.config.constants import ROOT_DIRECTORY_ID
from include.database.models.documents import Document, Folder
from include.database.models.identity import User
from include.messages import Messages as smsg

NODE_NAME_UNIQUE_CONSTRAINT = "uq_nodes_active_parent_name"


class NodeNameConflictError(RuntimeError):
    def __init__(self, parent_id: str, name: str) -> None:
        super().__init__(f"Node name {name!r} is already used under {parent_id!r}")
        self.parent_id = parent_id
        self.name = name


def is_node_name_conflict(exc: IntegrityError) -> bool:
    original = exc.orig
    message = str(original)
    lower_message = message.lower()
    if NODE_NAME_UNIQUE_CONSTRAINT in lower_message:
        return True

    sqlstate = getattr(original, "sqlstate", None) or getattr(original, "pgcode", None)
    diagnostic = getattr(original, "diag", None)
    if (
        sqlstate == "23505"
        and getattr(diagnostic, "constraint_name", None) == NODE_NAME_UNIQUE_CONSTRAINT
    ):
        return True

    error_args = getattr(original, "args", ())
    if error_args and error_args[0] == 1062:
        return NODE_NAME_UNIQUE_CONSTRAINT in lower_message

    sqlite_error_name = getattr(original, "sqlite_errorname", "")
    return sqlite_error_name in {"SQLITE_CONSTRAINT", "SQLITE_CONSTRAINT_UNIQUE"} and (
        "nodes.active_parent_id, nodes.name" in lower_message
        or "nodes.name, nodes.active_parent_id" in lower_message
    )


@contextmanager
def node_name_mutation(session: Session, parent_id: str, name: str) -> Iterator[None]:
    try:
        yield
    except IntegrityError as exc:
        if not is_node_name_conflict(exc):
            raise
        session.rollback()
        raise NodeNameConflictError(parent_id, name) from exc


def get_target_folder_and_check_write(
    session: Session, user: User, target_folder_id: str | None, super_permission: str
) -> tuple[Folder | None, int, str]:
    """
    Looks up the target folder, locks it, and checks write access.
    Returns (folder_object, error_code, error_message).
    If valid, error_code is 0.
    """
    if not target_folder_id:
        target_folder_id = ROOT_DIRECTORY_ID

    target_folder = (
        session.query(Folder).with_for_update().filter_by(id=target_folder_id).first()
    )
    if not target_folder:
        return None, 404, smsg.TARGET_DIRECTORY_NOT_FOUND

    if not target_folder.check_access_requirements(user, "write"):
        if (
            target_folder_id == ROOT_DIRECTORY_ID
            and super_permission in user.all_permissions
        ):
            return target_folder, 0, ""
        return None, 403, smsg.ACCESS_DENIED_WRITE_DIRECTORY

    return target_folder, 0, ""


def handle_name_duplicate(
    session: Session, user: User, folder_id: str | None, title: str
) -> tuple[bool, int, dict, str]:
    """
    Checks if a document or folder with `title` exists under `folder_id`.
    If yes, safely deletes deleted documents or returns conflict details.
    Returns: (has_conflict, error_code, error_data, error_message).
    If no conflict, returns (False, 0, {}, "").
    """
    if not folder_id:
        folder_id = ROOT_DIRECTORY_ID

    existing_doc = (
        session.query(Document)
        .with_for_update()
        .filter_by(folder_id=folder_id, title=title)
        .first()
    )
    existing_folder = (
        session.query(Folder)
        .with_for_update()
        .filter_by(parent_id=folder_id, name=title)
        .first()
    )

    if existing_doc:
        if existing_doc.active:
            resp_id = (
                existing_doc.id
                if existing_doc.check_access_requirements(user, "read")
                else None
            )
            payload = {"type": "document", "id": resp_id}
            if resp_id is not None:
                payload["duplicate_id"] = resp_id

            return (
                True,
                409,
                payload,
                smsg.DOCUMENT_NAME_DUPLICATE,
            )
        else:
            if existing_doc.check_access_requirements(user, "write"):
                try:
                    existing_doc.delete_all_revisions(do_commit=False)
                except PermissionError:
                    return (
                        True,
                        500,
                        {},
                        "Failed to delete revisions. Perhaps a file task is in progress?",
                    )
                session.delete(existing_doc)
                # Let caller commit
            else:
                resp_id = (
                    existing_doc.id
                    if existing_doc.check_access_requirements(user, "read")
                    else None
                )
                payload = {"type": "document", "id": resp_id}
                if resp_id is not None:
                    payload["duplicate_id"] = resp_id

                return (
                    True,
                    409,
                    payload,
                    getattr(
                        smsg,
                        "DENIED_FOR_DOC_NAME_DUPLICATE",
                        smsg.DOCUMENT_NAME_DUPLICATE,
                    ),
                )

    elif existing_folder:
        resp_id = (
            existing_folder.id
            if existing_folder.check_access_requirements(user, "read")
            else None
        )
        payload = {"type": "directory", "id": resp_id, "entity": existing_folder}
        if resp_id is not None:
            payload["duplicate_id"] = resp_id

        return (
            True,
            409,
            payload,
            smsg.DIRECTORY_NAME_DUPLICATE,
        )

    return False, 0, {}, ""

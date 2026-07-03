from sqlalchemy.exc import IntegrityError
from sqlalchemy.orm import Session

from include.config.constants import ROOT_DIRECTORY_ID
from include.config.settings import global_config
from include.database.models.documents import DirectoryNameLock, Document, Folder
from include.database.models.identity import User
from include.messages import Messages as smsg


def normalize_object_name(name: str) -> str:
    return name.strip()


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
    if global_config["document"]["allow_name_duplicate"]:
        return False, 0, {}, ""

    if not folder_id:
        folder_id = ROOT_DIRECTORY_ID
    title = normalize_object_name(title)

    existing_folder = (
        session.query(Folder)
        .with_for_update()
        .filter_by(parent_id=folder_id, name=title)
        .first()
    )
    existing_docs = (
        session.query(Document)
        .with_for_update()
        .filter_by(folder_id=folder_id, title=title)
        .all()
    )

    if existing_folder:
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

    inactive_docs: list[Document] = []
    for existing_doc in existing_docs:
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
        inactive_docs.append(existing_doc)

    for existing_doc in inactive_docs:
        if not existing_doc.check_access_requirements(user, "write"):
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

    for existing_doc in inactive_docs:
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

    return False, 0, {}, ""


def acquire_name_write_lock(
    session: Session, folder_id: str | None, title: str
) -> tuple[bool, int, dict, str]:
    if global_config["document"]["allow_name_duplicate"]:
        return False, 0, {}, ""

    if not folder_id:
        folder_id = ROOT_DIRECTORY_ID
    title = normalize_object_name(title)

    lock = DirectoryNameLock(parent_id=folder_id, name=title)
    session.add(lock)
    try:
        session.flush()
    except IntegrityError:
        session.rollback()
        return True, 409, {}, smsg.DOCUMENT_OR_DIRECTORY_NAME_DUPLICATE
    session.delete(lock)
    return False, 0, {}, ""

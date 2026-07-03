from dataclasses import dataclass, field
from typing import Any

from sqlalchemy.exc import IntegrityError
from sqlalchemy.orm import Session

from include.config.constants import ROOT_DIRECTORY_ID
from include.config.settings import global_config
from include.database.models.documents import DirectoryNameLock, Document, Folder
from include.database.models.identity import User
from include.messages import Messages as smsg


@dataclass(slots=True)
class NameConflict:
    code: int
    message: str
    data: dict[str, Any] = field(default_factory=dict)

    def public_data(self) -> dict[str, Any]:
        return {key: value for key, value in self.data.items() if key != "entity"}


def normalize_object_name(name: str) -> str:
    return name.strip()


def normalize_parent_id(folder_id: str | None) -> str:
    return folder_id or ROOT_DIRECTORY_ID


def get_target_folder_and_check_write(
    session: Session, user: User, target_folder_id: str | None, super_permission: str
) -> tuple[Folder | None, int, str]:
    """
    Looks up the target folder, locks it, and checks write access.
    Returns (folder_object, error_code, error_message).
    If valid, error_code is 0.
    """
    target_folder_id = normalize_parent_id(target_folder_id)

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


def _duplicate_payload(
    entity: Document | Folder,
    user: User,
    entity_type: str,
    *,
    include_entity: bool = False,
) -> dict[str, Any]:
    readable_id = entity.id if entity.check_access_requirements(user, "read") else None
    payload: dict[str, Any] = {"type": entity_type, "id": readable_id}
    if readable_id is not None:
        payload["duplicate_id"] = readable_id
    if include_entity:
        payload["entity"] = entity
    return payload


def find_name_conflict(
    session: Session, user: User, folder_id: str | None, title: str
) -> NameConflict | None:
    """
    Checks if a document or folder with `title` exists under `folder_id`.
    If yes, safely deletes deleted documents or returns conflict details.
    Returns a conflict when a live sibling folder/document already owns the name.
    Inactive documents are removed when the caller can write them, otherwise they
    still block reuse to avoid hiding objects the caller cannot safely replace.
    """
    if global_config["document"]["allow_name_duplicate"]:
        return None

    folder_id = normalize_parent_id(folder_id)
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
        return NameConflict(
            code=409,
            message=smsg.DIRECTORY_NAME_DUPLICATE,
            data=_duplicate_payload(
                existing_folder, user, "directory", include_entity=True
            ),
        )

    inactive_docs: list[Document] = []
    for existing_doc in existing_docs:
        if existing_doc.active:
            return NameConflict(
                code=409,
                message=smsg.DOCUMENT_NAME_DUPLICATE,
                data=_duplicate_payload(existing_doc, user, "document"),
            )
        inactive_docs.append(existing_doc)

    for existing_doc in inactive_docs:
        if not existing_doc.check_access_requirements(user, "write"):
            return NameConflict(
                code=409,
                message=getattr(
                    smsg,
                    "DENIED_FOR_DOC_NAME_DUPLICATE",
                    smsg.DOCUMENT_NAME_DUPLICATE,
                ),
                data=_duplicate_payload(existing_doc, user, "document"),
            )

    for existing_doc in inactive_docs:
        try:
            existing_doc.delete_all_revisions(do_commit=False)
        except PermissionError:
            return NameConflict(
                code=500,
                message="Failed to delete revisions. Perhaps a file task is in progress?",
            )
        session.delete(existing_doc)

    return None


def reserve_name_for_write(
    session: Session, user: User, folder_id: str | None, title: str
) -> tuple[DirectoryNameLock | None, NameConflict | None]:
    """
    Reserve a parent/name pair until the caller finishes its write.

    The returned lock must be released immediately before commit. Keeping it in
    the transaction until then serializes concurrent writers for names that do
    not yet exist in either the folders or documents table.
    """
    lock = acquire_name_write_lock(session, folder_id, title)
    if isinstance(lock, NameConflict):
        return None, lock

    conflict = find_name_conflict(session, user, folder_id, title)
    if conflict is not None:
        return None, conflict

    return lock, None


def acquire_name_write_lock(
    session: Session, folder_id: str | None, title: str
) -> DirectoryNameLock | NameConflict | None:
    if global_config["document"]["allow_name_duplicate"]:
        return None

    folder_id = normalize_parent_id(folder_id)
    title = normalize_object_name(title)

    lock = DirectoryNameLock(parent_id=folder_id, name=title)
    try:
        with session.begin_nested():
            session.add(lock)
            session.flush()
    except IntegrityError:
        return NameConflict(
            code=409,
            message=smsg.DOCUMENT_OR_DIRECTORY_NAME_DUPLICATE,
        )
    return lock


def release_name_write_lock(session: Session, lock: DirectoryNameLock | None) -> None:
    if lock is not None:
        session.delete(lock)

__all__ = [
    "load_document_access_context",
    "load_folder_access_context",
    "load_user_folder_access_context",
]

import time
from collections import defaultdict

from sqlalchemy import text
from sqlalchemy.orm import Session

from include.database.models.access import ObjectAccessEntry
from include.database.models.documents import Document, Folder
from include.database.models.identity import User


# Internal helper: expand ancestor chains and preload permission data for the
# starting folder IDs and target IDs that require OAE lookup.
def _fetch_ancestors_and_oae(
    session: Session,
    seed_folder_ids: list[str],  # Starting folder IDs for the recursive CTE.
    extra_target_ids: list[str],  # Non-folder target IDs requiring OAE lookup.
    exclude_folder_ids: set[str],  # Folder IDs already loaded and not queried again.
    now: float,
    entity_identifiers: set[str] | None = None,
    access_type: str | None = None,
) -> tuple[list[Folder], dict]:
    """
    Expand ancestors and preload access data.

    The recursive CTE starts from seed_folder_ids, loads ancestor folders with
    excluding exclude_folder_ids, and fetches ObjectAccessEntry rows for
    extra_target_ids plus all ancestor folders.

    Returns:
        ancestor_folders: Ancestor folders excluding exclude_folder_ids.
        oae_by_target: dict[target_id, list[ObjectAccessEntry]].
    """
    if not seed_folder_ids:
        # No ancestors need lookup, such as when all documents are in root.
        all_target_ids = extra_target_ids
        ancestor_folders = []
    else:
        # Step A: Expand all ancestor IDs with a recursive CTE and deduplicate.
        placeholders = ", ".join(f":fid_{i}" for i in range(len(seed_folder_ids)))
        params = {f"fid_{i}": fid for i, fid in enumerate(seed_folder_ids)}

        ancestor_sql = text(f"""
            WITH RECURSIVE anc(id, parent_id, inherit) AS (
                SELECT f.id, n.parent_id, n.inherit
                FROM folders f
                INNER JOIN nodes n ON n.id = f.id
                WHERE f.id IN ({placeholders})

                UNION

                SELECT f.id, n.parent_id, n.inherit
                FROM folders f
                INNER JOIN nodes n ON n.id = f.id
                INNER JOIN anc ON f.id = anc.parent_id
                WHERE anc.inherit = true
            )
            SELECT DISTINCT id FROM anc
        """)

        all_ancestor_ids = [
            row[0] for row in session.execute(ancestor_sql, params).fetchall()
        ]

        # Step B: Exclude already loaded IDs and bulk-load ancestor folders.
        pure_ancestor_ids = [
            fid for fid in all_ancestor_ids if fid not in exclude_folder_ids
        ]

        ancestor_folders = (
            (session.query(Folder).filter(Folder.id.in_(pure_ancestor_ids)).all())
            if pure_ancestor_ids
            else []
        )

        all_target_ids = extra_target_ids + all_ancestor_ids

    # Step C: Fetch OAE rows in bulk for documents and folders.
    oae_by_target: dict = defaultdict(list)
    if all_target_ids:
        oae_query = session.query(ObjectAccessEntry).filter(
            ObjectAccessEntry.target_identifier.in_(all_target_ids),
            ObjectAccessEntry.start_time <= now,
            (ObjectAccessEntry.end_time == None) | (ObjectAccessEntry.end_time >= now),
        )
        if entity_identifiers is not None:
            oae_query = oae_query.filter(
                ObjectAccessEntry.entity_identifier.in_(entity_identifiers)
            )
        if access_type is not None:
            oae_query = oae_query.filter(ObjectAccessEntry.access_type == access_type)
        oae_entries = oae_query.all()
        for entry in oae_entries:
            oae_by_target[entry.target_identifier].append(entry)

    return ancestor_folders, oae_by_target


def load_document_access_context(
    session: Session,
    documents: list[Document],
    now: float | None = None,
) -> tuple[list[Folder], dict]:
    if now is None:
        now = time.time()
    if not documents:
        return [], {}

    seed_folder_ids = list({doc.folder_id for doc in documents if doc.folder_id})
    return _fetch_ancestors_and_oae(
        session=session,
        seed_folder_ids=seed_folder_ids,
        extra_target_ids=[doc.id for doc in documents],
        exclude_folder_ids=set(),
        now=now,
    )


def load_folder_access_context(
    session: Session,
    folders: list[Folder],
    now: float | None = None,
) -> tuple[list[Folder], dict]:
    if now is None:
        now = time.time()
    if not folders:
        return [], {}

    seed_folder_ids = list({folder.parent_id for folder in folders if folder.parent_id})
    matched_ids = {folder.id for folder in folders}
    return _fetch_ancestors_and_oae(
        session=session,
        seed_folder_ids=seed_folder_ids,
        extra_target_ids=[folder.id for folder in folders],
        exclude_folder_ids=matched_ids,
        now=now,
    )


def load_user_folder_access_context(
    session: Session,
    folders: list[Folder],
    user: User,
    access_type: str,
    now: float | None = None,
) -> tuple[list[Folder], dict]:
    if now is None:
        now = time.time()
    if not folders:
        return [], {}

    seed_folder_ids = list({folder.parent_id for folder in folders if folder.parent_id})
    matched_ids = {folder.id for folder in folders}
    entity_identifiers = {user.username, *user.all_groups}
    return _fetch_ancestors_and_oae(
        session=session,
        seed_folder_ids=seed_folder_ids,
        extra_target_ids=[folder.id for folder in folders],
        exclude_folder_ids=matched_ids,
        now=now,
        entity_identifiers=entity_identifiers,
        access_type=access_type,
    )

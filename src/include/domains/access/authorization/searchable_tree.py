__all__ = [
    "search_documents_with_access",
    "search_folders_with_access",
]

import time
from collections import defaultdict
from typing import Optional

from sqlalchemy import text
from sqlalchemy.orm import Session, joinedload

from include.database.models.access import ObjectAccessEntry
from include.database.models.documents import Document, Folder


# Internal helper: expand ancestor chains and preload permission data for the
# starting folder IDs and target IDs that require OAE lookup.
def _fetch_ancestors_and_oae(
    session: Session,
    seed_folder_ids: list[str],  # Starting folder IDs for the recursive CTE.
    extra_target_ids: list[str],  # Non-folder target IDs requiring OAE lookup.
    exclude_folder_ids: set[str],  # Folder IDs already loaded and not queried again.
    now: float,
) -> tuple[list[Folder], dict]:
    """
    Expand ancestors and preload access data.

    The recursive CTE starts from seed_folder_ids, loads ancestor folders with
    access_rules preloaded while excluding exclude_folder_ids, and fetches
    ObjectAccessEntry rows for extra_target_ids plus all ancestor folders.

    Returns:
        ancestor_folders: Ancestor folders excluding exclude_folder_ids.
        oae_by_target: Dict[target_id, List[ObjectAccessEntry]].
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
                SELECT id, parent_id, inherit
                FROM folders
                WHERE id IN ({placeholders})

                UNION

                SELECT f.id, f.parent_id, f.inherit
                FROM folders f
                INNER JOIN anc ON f.id = anc.parent_id
            )
            SELECT DISTINCT id FROM anc
        """)

        all_ancestor_ids = [
            row[0] for row in session.execute(ancestor_sql, params).fetchall()
        ]

        # Step B: Exclude already loaded IDs and bulk-load ancestor folders with
        # access_rules.
        pure_ancestor_ids = [
            fid for fid in all_ancestor_ids if fid not in exclude_folder_ids
        ]

        ancestor_folders = (
            (
                session.query(Folder)
                .options(joinedload(Folder.access_rules))
                .filter(Folder.id.in_(pure_ancestor_ids))
                .all()
            )
            if pure_ancestor_ids
            else []
        )

        all_target_ids = extra_target_ids + all_ancestor_ids

    # Step C: Fetch OAE rows in bulk for documents and folders.
    oae_by_target: dict = defaultdict(list)
    if all_target_ids:
        oae_entries = (
            session.query(ObjectAccessEntry)
            .filter(
                ObjectAccessEntry.target_identifier.in_(all_target_ids),
                ObjectAccessEntry.start_time <= now,
                (ObjectAccessEntry.end_time == None)
                | (ObjectAccessEntry.end_time >= now),
            )
            .all()
        )
        for entry in oae_entries:
            oae_by_target[entry.target_identifier].append(entry)

    return ancestor_folders, oae_by_target


# Document search.
def search_documents_with_access(
    session: Session,
    keyword: str,
    now: Optional[float] = None,
) -> tuple[list[Document], list[Folder], dict]:
    """
    Search document titles by keyword and preload ancestor access data.

    Returns:
        documents: Matched documents with access_rules preloaded.
        folders: All ancestor folders with access_rules preloaded.
        oae_by_target: Dict[target_id, List[ObjectAccessEntry]].
    """
    if now is None:
        now = time.time()

    # Step 1: Search documents.
    documents = (
        session.query(Document)
        .options(joinedload(Document.access_rules))
        .filter(Document.title.ilike(f"%{keyword}%"))
        .all()
    )
    if not documents:
        return [], [], {}

    # Step 2: Collect direct parent folder IDs as deduplicated CTE seeds.
    seed_folder_ids = list({doc.folder_id for doc in documents if doc.folder_id})

    # Steps 3-5: Delegate to the shared helper.
    ancestor_folders, oae_by_target = _fetch_ancestors_and_oae(
        session=session,
        seed_folder_ids=seed_folder_ids,
        extra_target_ids=[doc.id for doc in documents],  # Documents also need OAE.
        exclude_folder_ids=set(),  # No folders are preloaded for document search.
        now=now,
    )

    return documents, ancestor_folders, oae_by_target


# Folder search.
def search_folders_with_access(
    session: Session,
    keyword: str,
    now: Optional[float] = None,
) -> tuple[list[Folder], list[Folder], dict]:
    """
    Search folder names by keyword and preload ancestor access data.

    Returns:
        matched_folders: Matched folders with access_rules preloaded.
        ancestor_folders: Ancestor folders with access_rules preloaded,
            excluding matched folders.
        oae_by_target: Dict[target_id, List[ObjectAccessEntry]].
    """
    if now is None:
        now = time.time()

    # Step 1: Search folders.
    matched_folders = (
        session.query(Folder)
        .options(joinedload(Folder.access_rules))
        .filter(Folder.name.ilike(f"%{keyword}%"))
        .all()
    )
    if not matched_folders:
        return [], [], {}

    # Step 2: Collect direct parent IDs as deduplicated seeds. Matched folders
    # are already loaded, so traversal starts from their parent_id.
    seed_folder_ids = list({f.parent_id for f in matched_folders if f.parent_id})

    matched_ids = {f.id for f in matched_folders}

    # Steps 3-5: Delegate to the shared helper. Exclude matched_ids to avoid
    # loading matched folders twice.
    ancestor_folders, oae_by_target = _fetch_ancestors_and_oae(
        session=session,
        seed_folder_ids=seed_folder_ids,
        extra_target_ids=[f.id for f in matched_folders],  # Matched folders need OAE.
        exclude_folder_ids=matched_ids,
        now=now,
    )

    return matched_folders, ancestor_folders, oae_by_target

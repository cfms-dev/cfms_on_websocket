__all__ = [
    "fetch_subtree_for_purge",
    "fetch_subtree_for_soft_delete",
]

from collections import defaultdict, deque
from itertools import batched

from sqlalchemy import text
from sqlalchemy.orm import Session

from include.config.constants import QUERY_CHUNK_SIZE
from include.database.models.documents import (
    Document,
    EntityStatus,
    Folder,
)


def _fetch_subtree_nodes(
    session: Session,
    root_folder_id: str,
    *,
    include_deleted: bool,
) -> tuple[list[Folder], list[Document]]:
    exec_opts = {"include_deleted": True} if include_deleted else {}
    status_filter = "" if include_deleted else f"AND n.status = {EntityStatus.OK.value}"

    subtree_sql = text(f"""
        WITH RECURSIVE subtree(id, parent_id, status) AS (
            SELECT f.id, n.parent_id, n.status
            FROM folders f
            INNER JOIN nodes n ON n.id = f.id
            WHERE f.id = :root_id

            UNION ALL

            SELECT f.id, n.parent_id, n.status
            FROM folders f
            INNER JOIN nodes n ON n.id = f.id
            INNER JOIN subtree s ON n.parent_id = s.id
            WHERE 1=1 {status_filter}
        )
        SELECT id FROM subtree WHERE id != :root_id
    """)
    descendant_folder_ids = [
        row[0]
        for row in session.execute(subtree_sql, {"root_id": root_folder_id}).fetchall()
    ]
    all_folder_ids = list(dict.fromkeys([root_folder_id, *descendant_folder_ids]))

    folders: list[Folder] = []
    for chunk in batched(all_folder_ids, QUERY_CHUNK_SIZE):
        folders.extend(
            session.query(Folder)
            .execution_options(**exec_opts)
            .filter(Folder.id.in_(list(chunk)))
            .all()
        )
    folder_by_id = {f.id: f for f in folders}

    # Topological order from deepest leaf up to root so callers can delete bottom-up.
    children_map: dict[str, list[str]] = defaultdict(list)
    parent_map: dict[str, str | None] = {}
    for folder in folders:
        parent_map[folder.id] = folder.parent_id
        if folder.parent_id and folder.parent_id in folder_by_id:
            children_map[folder.parent_id].append(folder.id)

    in_degree = {fid: len(children_map[fid]) for fid in folder_by_id}
    queue = deque([fid for fid in folder_by_id if in_degree[fid] == 0])
    ordered_descendant_folders: list[Folder] = []
    visited_count = 0
    while queue:
        fid = queue.popleft()
        visited_count += 1
        if fid != root_folder_id:
            ordered_descendant_folders.append(folder_by_id[fid])
        pid = parent_map.get(fid)
        if pid and pid in in_degree:
            in_degree[pid] -= 1
            if in_degree[pid] == 0:
                queue.append(pid)

    if visited_count != len(folder_by_id):
        raise RuntimeError("Cycle detected in folder hierarchy.")

    documents: list[Document] = []
    for chunk in batched(list(folder_by_id.keys()), QUERY_CHUNK_SIZE):
        query = (
            session.query(Document)
            .execution_options(**exec_opts)
            .filter(Document.folder_id.in_(list(chunk)))
        )
        if not include_deleted:
            query = query.filter(Document.status == EntityStatus.OK)
        documents.extend(query.all())

    return ordered_descendant_folders, documents


def fetch_subtree_for_soft_delete(
    session: Session,
    root_folder_id: str,
) -> tuple[list[Folder], list[Document]]:
    """Return all non-deleted descendant folders (deepest first) and documents."""
    return _fetch_subtree_nodes(session, root_folder_id, include_deleted=False)


def fetch_subtree_for_purge(
    session: Session,
    root_folder_id: str,
) -> tuple[list[str], list[str]]:
    """Return all descendant folder IDs (deepest first) and document IDs for cascading purge."""
    folders, documents = _fetch_subtree_nodes(
        session, root_folder_id, include_deleted=True
    )
    return [f.id for f in folders], [d.id for d in documents]

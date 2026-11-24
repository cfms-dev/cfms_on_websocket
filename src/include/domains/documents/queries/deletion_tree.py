__all__ = [
    "SubtreeNodeRow",
    "fetch_subtree_for_purge",
    "fetch_subtree_ids_for_soft_delete",
    "fetch_subtree_metadata_for_soft_delete",
]

from collections import defaultdict, deque
from dataclasses import dataclass
from itertools import batched

from sqlalchemy import select
from sqlalchemy.orm import Session

from include.config.constants import QUERY_CHUNK_SIZE
from include.database.models.documents import (
    EntityStatus,
    Node,
    NodeType,
)


@dataclass(frozen=True, slots=True)
class SubtreeNodeRow:
    id: str
    name: str
    parent_id: str | None
    type: str
    status: int
    inherit: bool


def _fetch_subtree_rows(
    session: Session,
    root_folder_id: str,
    *,
    include_deleted: bool,
) -> tuple[list[SubtreeNodeRow], list[SubtreeNodeRow]]:
    node_table = Node.__table__
    anchor = select(
        node_table.c.id.label("id"),
        node_table.c.name.label("name"),
        node_table.c.parent_id.label("parent_id"),
        node_table.c.type.label("type"),
        node_table.c.status.label("status"),
        node_table.c.inherit.label("inherit"),
    ).where(
        node_table.c.id == root_folder_id,
        node_table.c.type == NodeType.DIRECTORY.value,
    )
    subtree = anchor.cte("deletion_subtree", recursive=True)
    child_node = node_table.alias("deletion_child_node")
    recursive_filters = [child_node.c.type == NodeType.DIRECTORY.value]
    if not include_deleted:
        recursive_filters.append(child_node.c.status == EntityStatus.OK.value)
    subtree = subtree.union_all(
        select(
            child_node.c.id,
            child_node.c.name,
            child_node.c.parent_id,
            child_node.c.type,
            child_node.c.status,
            child_node.c.inherit,
        )
        .select_from(subtree.join(child_node, child_node.c.parent_id == subtree.c.id))
        .where(*recursive_filters)
    )

    folder_by_id: dict[str, SubtreeNodeRow] = {}
    for nid, name, parent_id, node_type, status, inherit_flag in session.execute(
        select(
            subtree.c.id,
            subtree.c.name,
            subtree.c.parent_id,
            subtree.c.type,
            subtree.c.status,
            subtree.c.inherit,
        )
    ).all():
        if nid not in folder_by_id:
            folder_by_id[nid] = SubtreeNodeRow(
                id=nid,
                name=name,
                parent_id=parent_id,
                type=node_type,
                status=int(status),
                inherit=bool(inherit_flag),
            )

    if not folder_by_id:
        return [], []

    # Topological order from deepest leaf up to root so callers can delete bottom-up.
    children_map: dict[str, list[str]] = defaultdict(list)
    parent_map: dict[str, str | None] = {}
    for fid, folder in folder_by_id.items():
        parent_map[fid] = folder.parent_id
        if folder.parent_id and folder.parent_id in folder_by_id:
            children_map[folder.parent_id].append(fid)

    in_degree = {fid: len(children_map[fid]) for fid in folder_by_id}
    queue = deque([fid for fid in folder_by_id if in_degree[fid] == 0])
    ordered_descendant_folders: list[SubtreeNodeRow] = []
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

    documents: list[SubtreeNodeRow] = []
    for chunk in batched(list(folder_by_id.keys()), QUERY_CHUNK_SIZE):
        doc_stmt = select(
            node_table.c.id,
            node_table.c.name,
            node_table.c.parent_id,
            node_table.c.type,
            node_table.c.status,
            node_table.c.inherit,
        ).where(
            node_table.c.parent_id.in_(list(chunk)),
            node_table.c.type == NodeType.DOCUMENT.value,
        )
        if not include_deleted:
            doc_stmt = doc_stmt.where(node_table.c.status == EntityStatus.OK.value)
        for nid, name, parent_id, node_type, status, inherit_flag in session.execute(
            doc_stmt
        ).all():
            documents.append(
                SubtreeNodeRow(
                    id=nid,
                    name=name,
                    parent_id=parent_id,
                    type=node_type,
                    status=int(status),
                    inherit=bool(inherit_flag),
                )
            )

    return ordered_descendant_folders, documents


def fetch_subtree_metadata_for_soft_delete(
    session: Session,
    root_folder_id: str,
) -> tuple[list[SubtreeNodeRow], list[SubtreeNodeRow]]:
    """Return lightweight metadata for all non-deleted descendant folders (deepest first) and documents."""
    return _fetch_subtree_rows(session, root_folder_id, include_deleted=False)


def fetch_subtree_ids_for_soft_delete(
    session: Session,
    root_folder_id: str,
) -> tuple[list[str], list[str]]:
    """Return all non-deleted descendant folder IDs (deepest first) and document IDs."""
    folders, documents = _fetch_subtree_rows(
        session, root_folder_id, include_deleted=False
    )
    return [f.id for f in folders], [d.id for d in documents]


def fetch_subtree_for_purge(
    session: Session,
    root_folder_id: str,
) -> tuple[list[str], list[str]]:
    """Return all descendant folder IDs (deepest first) and document IDs for cascading purge."""
    folders, documents = _fetch_subtree_rows(
        session, root_folder_id, include_deleted=True
    )
    return [f.id for f in folders], [d.id for d in documents]

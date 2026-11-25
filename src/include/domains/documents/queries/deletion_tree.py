__all__ = [
    "SubtreeNodeRow",
    "fetch_subtree_ids_for_soft_delete",
    "fetch_subtree_metadata_for_purge",
    "fetch_subtree_metadata_for_restore",
    "fetch_subtree_metadata_for_soft_delete",
]

from collections import defaultdict, deque
from dataclasses import dataclass
from itertools import batched

from sqlalchemy import literal, select
from sqlalchemy.orm import Session

from include.config.constants import MAX_HIERARCHY_DEPTH, QUERY_CHUNK_SIZE
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


def _query_subtree_folders(
    session: Session,
    root_folder_id: str,
    *,
    include_deleted: bool,
    status_operation_id: str | None = None,
) -> dict[str, SubtreeNodeRow]:
    node_table = Node.__table__
    anchor = select(
        node_table.c.id.label("id"),
        node_table.c.name.label("name"),
        node_table.c.parent_id.label("parent_id"),
        node_table.c.type.label("type"),
        node_table.c.status.label("status"),
        node_table.c.inherit.label("inherit"),
        literal(0).label("depth"),
    ).where(
        node_table.c.id == root_folder_id,
        node_table.c.type == NodeType.DIRECTORY.value,
    )
    subtree = anchor.cte("deletion_subtree", recursive=True)
    child_node = node_table.alias("deletion_child_node")
    recursive_filters = [
        child_node.c.type == NodeType.DIRECTORY.value,
        child_node.c.id != root_folder_id,
        subtree.c.depth <= MAX_HIERARCHY_DEPTH,
    ]
    if status_operation_id is not None:
        recursive_filters.extend(
            (
                child_node.c.status == EntityStatus.DELETED.value,
                child_node.c.status_operation_id == status_operation_id,
            )
        )
    elif not include_deleted:
        recursive_filters.append(child_node.c.status != EntityStatus.DELETED.value)
    subtree = subtree.union_all(
        select(
            child_node.c.id,
            child_node.c.name,
            child_node.c.parent_id,
            child_node.c.type,
            child_node.c.status,
            child_node.c.inherit,
            (subtree.c.depth + 1).label("depth"),
        )
        .select_from(subtree.join(child_node, child_node.c.parent_id == subtree.c.id))
        .where(*recursive_filters)
    )

    folder_by_id: dict[str, SubtreeNodeRow] = {}
    for nid, name, parent_id, node_type, status, inherit_flag, depth in session.execute(
        select(
            subtree.c.id,
            subtree.c.name,
            subtree.c.parent_id,
            subtree.c.type,
            subtree.c.status,
            subtree.c.inherit,
            subtree.c.depth,
        )
    ).all():
        if int(depth) > MAX_HIERARCHY_DEPTH:
            raise RuntimeError(
                f"Directory subtree depth exceeded limit ({MAX_HIERARCHY_DEPTH})."
            )
        if nid not in folder_by_id:
            folder_by_id[nid] = SubtreeNodeRow(
                id=nid,
                name=name,
                parent_id=parent_id,
                type=node_type,
                status=int(status),
                inherit=bool(inherit_flag),
            )
    return folder_by_id


def _order_descendant_folders_bottom_up(
    folder_by_id: dict[str, SubtreeNodeRow],
    root_folder_id: str,
) -> list[SubtreeNodeRow]:
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
    return ordered_descendant_folders


def _query_subtree_documents(
    session: Session,
    folder_ids: list[str],
    *,
    include_deleted: bool,
    status_operation_id: str | None = None,
) -> list[SubtreeNodeRow]:
    node_table = Node.__table__
    documents: list[SubtreeNodeRow] = []
    for chunk in batched(folder_ids, QUERY_CHUNK_SIZE):
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
        if status_operation_id is not None:
            doc_stmt = doc_stmt.where(
                node_table.c.status == EntityStatus.DELETED.value,
                node_table.c.status_operation_id == status_operation_id,
            )
        elif not include_deleted:
            doc_stmt = doc_stmt.where(node_table.c.status != EntityStatus.DELETED.value)
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
    return documents


def _fetch_subtree_rows(
    session: Session,
    root_folder_id: str,
    *,
    include_deleted: bool,
    status_operation_id: str | None = None,
) -> tuple[list[SubtreeNodeRow], list[SubtreeNodeRow]]:
    folder_by_id = _query_subtree_folders(
        session,
        root_folder_id,
        include_deleted=include_deleted,
        status_operation_id=status_operation_id,
    )
    if not folder_by_id:
        return [], []
    ordered_descendant_folders = _order_descendant_folders_bottom_up(
        folder_by_id, root_folder_id
    )
    documents = _query_subtree_documents(
        session,
        list(folder_by_id.keys()),
        include_deleted=include_deleted,
        status_operation_id=status_operation_id,
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


def fetch_subtree_metadata_for_purge(
    session: Session,
    root_folder_id: str,
) -> tuple[list[SubtreeNodeRow], list[SubtreeNodeRow]]:
    """Return lightweight metadata for all descendant folders (deepest first) and documents for cascading purge."""
    return _fetch_subtree_rows(session, root_folder_id, include_deleted=True)


def fetch_subtree_metadata_for_restore(
    session: Session,
    root_folder_id: str,
    status_operation_id: str,
) -> tuple[list[SubtreeNodeRow], list[SubtreeNodeRow]]:
    """Return lightweight metadata for soft-deleted descendants matching status_operation_id."""
    if not status_operation_id:
        return [], []
    return _fetch_subtree_rows(
        session,
        root_folder_id,
        include_deleted=True,
        status_operation_id=status_operation_id,
    )

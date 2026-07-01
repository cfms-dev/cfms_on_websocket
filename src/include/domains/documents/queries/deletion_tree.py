import time
from collections import defaultdict, deque
from itertools import batched

from sqlalchemy import text
from sqlalchemy.orm import Session, joinedload

from include.config.constants import QUERY_CHUNK_SIZE
from include.database.models.access import ObjectAccessEntry
from include.database.models.documents import (
    Document,
    DocumentRevision,
    EntityStatus,
    Folder,
)
from include.database.models.identity import User
from include.domains.access.authorization.evaluation import check_access_for_object
from include.domains.access.authorization.grants import prefetch_user_blocks


def fetch_subtree_for_deletion(
    session: Session,
    root_folder_id: str,
    user: User,
    now: float | None = None,
    include_deleted: bool = False,
) -> tuple[
    list[str],  # deletable_folder_ids: ordered
    set[str],  # deletable_doc_ids
    list[dict],  # failed_items
    set[str],  # protected_folder_ids
    dict[str, Folder],  # folder_map
]:
    """
    Analyze whether the subtree under root_folder_id can be deleted.

    Returns:
        deletable_folder_ids: Folder IDs that can be deleted, ordered deepest first.
        deletable_doc_ids: Document IDs that can be deleted.
        failed_items: Permission-failed items for client responses.
        protected_folder_ids: Folder IDs kept because of undeletable descendants.
        folder_map: Mapping from folder ID to Folder ORM object.
    """
    if now is None:
        now = time.time()

    # Step 1: Fetch all folder IDs in the subtree with a recursive CTE.
    exec_opts = {"include_deleted": True} if include_deleted else {}
    status_filter = "" if include_deleted else f"AND f.status = {EntityStatus.OK.value}"

    subtree_sql = text(f"""
        WITH RECURSIVE subtree(id, parent_id, status) AS (
            SELECT id, parent_id, status
            FROM folders
            WHERE id = :root_id

            UNION ALL

            SELECT f.id, f.parent_id, f.status
            FROM folders f
            INNER JOIN subtree s ON f.parent_id = s.id
            WHERE 1=1 {status_filter}
        )
        SELECT id FROM subtree WHERE id != :root_id
        """)
    # The caller has already checked whether root_id itself can be deleted.
    # This function analyzes only its contents. Remove WHERE id != :root_id to
    # include the root itself.

    all_subfolder_ids = [
        row[0]
        for row in session.execute(subtree_sql, {"root_id": root_folder_id}).fetchall()
    ]

    # Also load the root itself for the later BFS derivation.
    all_folder_ids_to_load = list(set(all_subfolder_ids + [root_folder_id]))

    # Step 2: Load all folders in bulk, including access_rules.
    # Chunked to avoid SQLite bind-variable limit for large subtrees.
    folders: list[Folder] = []
    for chunk in batched(all_folder_ids_to_load, QUERY_CHUNK_SIZE):
        folders.extend(
            session.query(Folder)
            .options(joinedload(Folder.access_rules))
            .execution_options(**exec_opts)
            .filter(Folder.id.in_(list(chunk)))
            .all()
        )
    folder_map: dict[str, Folder] = {f.id: f for f in folders}
    actual_folder_ids = list(folder_map.keys())

    # Step 3: Load all subtree documents, including access rules, revisions,
    # and files.
    # Chunked to avoid SQLite bind-variable limit for large subtrees.
    documents: list[Document] = []
    for chunk in batched(actual_folder_ids, QUERY_CHUNK_SIZE):
        documents.extend(
            session.query(Document)
            .options(
                joinedload(Document.access_rules),
                joinedload(Document.current_revision).joinedload(DocumentRevision.file),
            )
            .execution_options(**exec_opts)
            .filter(Document.folder_id.in_(list(chunk)))
            .all()
        )

    # Step 4: Prefetch OAE rows in bulk.
    # Chunked to avoid bind-variable limit for large subtrees.
    all_target_ids = actual_folder_ids + [doc.id for doc in documents]
    oae_entries: list[ObjectAccessEntry] = []
    for chunk in batched(all_target_ids, QUERY_CHUNK_SIZE):
        oae_entries.extend(
            session.query(ObjectAccessEntry)
            .execution_options(**exec_opts)
            .filter(
                ObjectAccessEntry.target_identifier.in_(list(chunk)),
                ObjectAccessEntry.start_time <= now,
                (ObjectAccessEntry.end_time == None)
                | (ObjectAccessEntry.end_time >= now),
            )
            .all()
        )
    oae_by_target: dict = defaultdict(list)
    for entry in oae_entries:
        oae_by_target[entry.target_identifier].append(entry)

    # Step 5: Prefetch user block state once to avoid repeated queries.
    is_globally_blocked, blocked_write_ids = prefetch_user_blocks(
        session, user, "write", now
    )

    # Step 6: Check permissions for each document. check_access_for_object uses
    # preloaded all_folders and oae_by_target, so it does not emit extra SQL.
    deletable_doc_ids: set[str] = set()
    failed_items: list[dict] = []

    has_delete_document_perm = "delete_document" in user.all_permissions

    for doc in documents:
        if not include_deleted and doc.status != EntityStatus.OK:
            continue

        can_delete = (
            not is_globally_blocked
            and doc.id not in blocked_write_ids
            and has_delete_document_perm
            and check_access_for_object(
                doc,
                user,
                "write",
                all_folders=folders,
                oae_by_target=oae_by_target,
            )
        )

        if can_delete:
            deletable_doc_ids.add(doc.id)
        else:
            assert doc.folder_id is not None
            if check_access_for_object(
                folder_map[doc.folder_id],
                user,
                "read",
                all_folders=folders,
                oae_by_target=oae_by_target,
            ):
                failed_items.append(
                    {
                        "type": "document",
                        "id": doc.id,
                        "title": doc.title,
                        "parent_folder_id": doc.folder_id,
                        "reason": "permission_denied",
                    }
                )

    # Step 7: Check each child folder's own permissions.
    has_delete_directory_perm = "delete_directory" in user.all_permissions

    # folder_self_deletable considers only the folder itself, not descendants.
    folder_self_deletable: dict[str, bool] = {}

    for folder in folders:
        if folder.id == root_folder_id:
            # The handler already authorized the root itself, so assume deletable.
            folder_self_deletable[folder.id] = True
            continue

        can_delete = (
            not is_globally_blocked
            and folder.id not in blocked_write_ids
            and has_delete_directory_perm
            and check_access_for_object(
                folder,
                user,
                "write",
                all_folders=folders,
                oae_by_target=oae_by_target,
            )
        )
        folder_self_deletable[folder.id] = can_delete
        if not can_delete:
            assert folder.parent_id is not None, (
                "Root folder should have been handled separately"
            )
            if check_access_for_object(
                folder_map[folder.parent_id],
                user,
                "read",
                all_folders=folders,
                oae_by_target=oae_by_target,
            ):
                failed_items.append(
                    {
                        "type": "folder",
                        "id": folder.id,
                        "name": folder.name,
                        "parent_folder_id": folder.parent_id,
                        "reason": "permission_denied",
                    }
                )

    # Step 8: Derive folders that must be kept because they contain undeletable
    # descendants. Build a leaf-to-root topological order and bubble state up.

    # Build parent-child relation maps.
    children_map: dict[str, list[str]] = defaultdict(list)
    parent_map: dict[str, str | None] = {}
    for folder in folders:
        parent_map[folder.id] = folder.parent_id
        if folder.parent_id and folder.parent_id in set(actual_folder_ids):
            children_map[folder.parent_id].append(folder.id)

    # Record whether each folder contains undeletable content. A folder with
    # insufficient self permissions is treated as undeletable for its parent.
    has_undeletable_content: dict[str, bool] = {}

    # Process nodes in leaf-to-root topological order. Start with leaves, which
    # have no child folders in the subtree.

    in_degree = {fid: len(children_map[fid]) for fid in actual_folder_ids}
    queue = deque([fid for fid in actual_folder_ids if in_degree[fid] == 0])

    topo_order = []
    while queue:
        fid = queue.popleft()
        topo_order.append(fid)
        parent_id = parent_map.get(fid)
        if parent_id and parent_id in in_degree:
            in_degree[parent_id] -= 1
            if in_degree[parent_id] == 0:
                queue.append(parent_id)

    if len(topo_order) != len(actual_folder_ids):
        raise RuntimeError("Cycle detected in folder hierarchy.")

    # Calculate has_undeletable_content in leaf-to-root order. Documents count
    # as undeletable content for their containing folder.
    folder_has_undeletable_doc: dict[str, bool] = defaultdict(bool)
    for doc in documents:
        is_active = (
            doc.current_revision is not None and doc.current_revision.file.active
        )
        if is_active and doc.id not in deletable_doc_ids:
            if doc.folder_id:
                folder_has_undeletable_doc[doc.folder_id] = True

    for fid in topo_order:
        self_undeletable = not folder_self_deletable.get(fid, True)
        child_undeletable = any(
            has_undeletable_content.get(child_fid, False)
            for child_fid in children_map[fid]
        )
        doc_undeletable = folder_has_undeletable_doc.get(fid, False)
        has_undeletable_content[fid] = (
            self_undeletable or child_undeletable or doc_undeletable
        )

    # Step 9: Generate the final ordered result from topo_order.
    deletable_folder_ids: list[str] = []
    protected_folder_ids: set[str] = set()

    # Since topo_order runs from leaves to root, deletable_folder_ids will also
    # delete child folders before parent folders.
    for fid in topo_order:
        # Skip root_folder_id; external handler logic decides how to handle it.
        if fid == root_folder_id:
            continue

        # A folder is deletable only when it is deletable itself and has no
        # undeletable descendants.
        can_delete_folder = folder_self_deletable.get(
            fid, False
        ) and not has_undeletable_content.get(fid, False)

        if can_delete_folder:
            deletable_folder_ids.append(fid)
        else:
            protected_folder_ids.add(fid)

    return (
        deletable_folder_ids,  # Ordered from deepest to shallowest.
        deletable_doc_ids,
        failed_items,
        protected_folder_ids,
        folder_map,
    )

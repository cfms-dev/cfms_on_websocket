__all__ = [
    "authorize_dacl_save",
    "authorize_directory_soft_delete",
    "authorize_node_operation",
    "authorize_reparent",
    "authorize_restore",
    "has_bypass_dacl",
    "load_ancestor_path",
    "load_ancestor_paths_for_nodes",
    "node_to_object_state",
    "node_to_object_type",
    "should_check_ancestor_traverse",
    "user_to_subject",
]

import datetime
from collections.abc import Sequence
from itertools import batched

from cacl_compiler import (
    AtomicOp,
    CompiledPolicy,
    EvalDecision,
    NamespaceNode,
    ObjectState,
    ObjectType,
    SaveAuthzResult,
    Subject,
    authorize_policy_save,
    evaluate_access,
    evaluate_effective_masks,
    evaluate_reparent,
    evaluate_soft_delete,
)
from cacl_compiler.permissions import op_applies_to_object, op_applies_to_state
from sqlalchemy import literal, select
from sqlalchemy.orm import Session as OrmSession

from include.config.constants import QUERY_CHUNK_SIZE
from include.config.options import CORE_OPTIONS, read_option
from include.database.models.documents import (
    Document,
    EntityStatus,
    Folder,
    Node,
    NodeType,
)
from include.database.models.identity import User
from include.domains.access.authorization.storage import load_node_policies
from include.domains.access.permissions import Permissions


def has_bypass_dacl(user: User) -> bool:
    return Permissions.BYPASS_DACL in user.all_permissions


def user_to_subject(user: User) -> Subject:
    return Subject(
        user_id=user.id,
        username=user.username,
        groups=frozenset(user.all_groups),
        perms=frozenset(str(perm) for perm in user.all_permissions),
    )


def should_check_ancestor_traverse(session: OrmSession, user: User) -> bool:
    if Permissions.BYPASS_TRAVERSE_CHECKING in user.all_permissions:
        return False
    bypass_option = read_option(session, "access", CORE_OPTIONS["access"][0]).value
    return not bool(bypass_option)


def node_to_object_type(node: Document | Folder | Node) -> ObjectType:
    if isinstance(node, Document) or node.type == NodeType.DOCUMENT.value:
        return ObjectType.DOCUMENT
    return ObjectType.DIRECTORY


def node_to_object_state(node: Document | Folder | Node) -> ObjectState:
    if node.status == EntityStatus.DELETED:
        return ObjectState.SOFT_DELETED
    return ObjectState.NORMAL


def load_ancestor_paths_for_nodes(
    session: OrmSession,
    targets: Sequence[Document | Folder],
    *,
    include_deleted: bool = False,
) -> dict[str, list[NamespaceNode]]:
    """Bulk-load root-to-node NamespaceNode paths for a batch of targets."""
    if not targets:
        return {}

    target_ids = list(dict.fromkeys(t.id for t in targets))
    node_table = Node.__table__
    all_node_rows: dict[str, tuple[str, str, str | None, str, int]] = {}

    for chunk in batched(target_ids, QUERY_CHUNK_SIZE):
        chunk_ids = list(chunk)
        anchor = select(
            node_table.c.id.label("id"),
            node_table.c.name.label("name"),
            node_table.c.parent_id.label("parent_id"),
            node_table.c.type.label("type"),
            node_table.c.status.label("status"),
            literal(0).label("depth"),
        ).where(node_table.c.id.in_(chunk_ids))

        ancestors = anchor.cte("cacl_ancestor_chain", recursive=True)
        parent_node = node_table.alias("cacl_parent_node")
        ancestors = ancestors.union(
            select(
                parent_node.c.id,
                parent_node.c.name,
                parent_node.c.parent_id,
                parent_node.c.type,
                parent_node.c.status,
                (ancestors.c.depth + 1).label("depth"),
            )
            .select_from(
                ancestors.join(parent_node, parent_node.c.id == ancestors.c.parent_id)
            )
            .where(ancestors.c.parent_id.is_not(None), ancestors.c.depth < 128)
        )

        rows = session.execute(
            select(
                ancestors.c.id,
                ancestors.c.name,
                ancestors.c.parent_id,
                ancestors.c.type,
                ancestors.c.status,
            ).distinct()
        ).all()
        for nid, name, parent_id, node_type, status in rows:
            all_node_rows[nid] = (nid, name, parent_id, node_type, status)

    # Ensure in-memory unflushed target state (e.g. newly created or modified nodes) is authoritative.
    for target in targets:
        all_node_rows[target.id] = (
            target.id,
            target.name,
            target.parent_id,
            target.type,
            int(target.status),
        )

    policies = load_node_policies(
        session, list(all_node_rows.keys()), include_deleted=True
    )

    namespace_nodes: dict[str, NamespaceNode] = {}
    for nid, (_id, name, _parent_id, node_type, status) in all_node_rows.items():
        obj_type = (
            ObjectType.DOCUMENT
            if node_type == NodeType.DOCUMENT.value
            else ObjectType.DIRECTORY
        )
        obj_state = (
            ObjectState.SOFT_DELETED
            if status == EntityStatus.DELETED.value
            else ObjectState.NORMAL
        )
        policy = policies.get(nid, CompiledPolicy(inherit=True, rules=()))
        namespace_nodes[nid] = NamespaceNode(
            node_id=nid,
            name=name,
            object_type=obj_type,
            state=obj_state,
            policy=policy,
        )

    result: dict[str, list[NamespaceNode]] = {}
    for target in targets:
        chain: list[NamespaceNode] = []
        visited: set[str] = set()
        curr_id: str | None = target.id
        while curr_id is not None:
            if curr_id in visited:
                raise RuntimeError(f"Cycle detected in folder hierarchy at {curr_id!r}")
            visited.add(curr_id)
            row = all_node_rows.get(curr_id)
            if row is None:
                break
            chain.append(namespace_nodes[curr_id])
            curr_id = row[2]
        chain.reverse()
        result[target.id] = chain
    return result


def load_ancestor_path(
    session: OrmSession,
    target: Document | Folder,
    *,
    include_deleted: bool = False,
) -> list[NamespaceNode]:
    return load_ancestor_paths_for_nodes(
        session, [target], include_deleted=include_deleted
    )[target.id]


def _check_step1_invariants(
    target: Document | Folder,
    operation: AtomicOp,
) -> EvalDecision | None:
    obj_type = node_to_object_type(target)
    obj_state = node_to_object_state(target)
    if not op_applies_to_object(operation, obj_type):
        return EvalDecision(
            allowed=False,
            reason=f"Operation {operation.name} is not applicable to {obj_type.value}.",
            step="1_lifecycle_and_type",
        )
    if not op_applies_to_state(operation, obj_state):
        return EvalDecision(
            allowed=False,
            reason=f"Operation {operation.name} is not applicable in state {obj_state.value}.",
            step="1_lifecycle_and_type",
        )
    return None


def authorize_node_operation(
    session: OrmSession,
    user: User,
    target: Document | Folder,
    operation: AtomicOp,
    *,
    include_deleted: bool = False,
    eval_time_utc: datetime.datetime | None = None,
) -> EvalDecision:
    """Evaluate CEP-0002 access for a single operation on a Document or Folder."""
    step1_denial = _check_step1_invariants(target, operation)
    if step1_denial is not None:
        return step1_denial

    if has_bypass_dacl(user):
        return EvalDecision(
            allowed=True,
            reason="Allowed by global BYPASS_DACL capability.",
            step="0_bypass_dacl",
        )

    now = eval_time_utc or datetime.datetime.now(datetime.UTC)
    path = load_ancestor_path(session, target, include_deleted=include_deleted)
    return evaluate_access(
        user_to_subject(user),
        path,
        operation,
        eval_time_utc=now,
        check_ancestor_traverse=should_check_ancestor_traverse(session, user),
    )


def authorize_reparent(
    session: OrmSession,
    user: User,
    source: Document | Folder,
    dest_parent: Folder,
    *,
    eval_time_utc: datetime.datetime | None = None,
) -> EvalDecision:
    """Evaluate CEP-0002 Step 5 composite reparent (REPARENT on source + CREATE_* on dest)."""
    if has_bypass_dacl(user):
        src_step1 = _check_step1_invariants(source, AtomicOp.REPARENT)
        if src_step1 is not None:
            return src_step1
        dest_op = (
            AtomicOp.CREATE_DOCUMENT
            if isinstance(source, Document)
            else AtomicOp.CREATE_DIRECTORY
        )
        dst_step1 = _check_step1_invariants(dest_parent, dest_op)
        if dst_step1 is not None:
            return dst_step1
        return EvalDecision(
            allowed=True,
            reason="Allowed by global BYPASS_DACL capability.",
            step="0_bypass_dacl",
        )

    now = eval_time_utc or datetime.datetime.now(datetime.UTC)
    paths = load_ancestor_paths_for_nodes(session, [source, dest_parent])
    return evaluate_reparent(
        user_to_subject(user),
        paths[source.id],
        paths[dest_parent.id],
        eval_time_utc=now,
        also_rename=False,
        check_ancestor_traverse=should_check_ancestor_traverse(session, user),
    )


def authorize_directory_soft_delete(
    session: OrmSession,
    user: User,
    target: Folder,
    descendants: Sequence[Document | Folder],
    *,
    eval_time_utc: datetime.datetime | None = None,
) -> EvalDecision:
    """Evaluate CEP-0002 Step 5 atomic soft-delete for a directory and its descendants."""
    step1_denial = _check_step1_invariants(target, AtomicOp.DELETE)
    if step1_denial is not None:
        return step1_denial

    if has_bypass_dacl(user):
        return EvalDecision(
            allowed=True,
            reason="Allowed by global BYPASS_DACL capability.",
            step="0_bypass_dacl",
        )

    now = eval_time_utc or datetime.datetime.now(datetime.UTC)
    all_nodes: list[Document | Folder] = [target, *descendants]
    paths = load_ancestor_paths_for_nodes(session, all_nodes)
    return evaluate_soft_delete(
        user_to_subject(user),
        paths[target.id],
        [paths[node.id] for node in descendants],
        eval_time_utc=now,
        check_ancestor_traverse=should_check_ancestor_traverse(session, user),
    )


def authorize_restore(
    session: OrmSession,
    user: User,
    target: Document | Folder,
    target_parent: Folder,
    *,
    eval_time_utc: datetime.datetime | None = None,
) -> EvalDecision:
    """Evaluate CEP-0002 RESTORE on a soft-deleted node (and CREATE_* if reparenting)."""
    step1_denial = _check_step1_invariants(target, AtomicOp.RESTORE)
    if step1_denial is not None:
        return step1_denial

    if target_parent.status != EntityStatus.OK:
        return EvalDecision(
            allowed=False,
            reason="Target parent directory must be in the normal state.",
            step="1_lifecycle_and_type",
        )

    reparenting = (target.parent_id or "/") != target_parent.id
    dest_op = (
        AtomicOp.CREATE_DOCUMENT
        if isinstance(target, Document)
        else AtomicOp.CREATE_DIRECTORY
    )

    if has_bypass_dacl(user):
        return EvalDecision(
            allowed=True,
            reason="Allowed by global BYPASS_DACL capability.",
            step="0_bypass_dacl",
        )

    now = eval_time_utc or datetime.datetime.now(datetime.UTC)
    check_traverse = should_check_ancestor_traverse(session, user)
    subject = user_to_subject(user)
    paths = load_ancestor_paths_for_nodes(
        session, [target, target_parent], include_deleted=True
    )
    target_path = paths[target.id]

    if not reparenting:
        restore_decision = evaluate_access(
            subject,
            target_path,
            AtomicOp.RESTORE,
            eval_time_utc=now,
            check_ancestor_traverse=check_traverse,
        )
        if not restore_decision.allowed:
            return restore_decision
        return restore_decision

    # When restoring into a different active parent, evaluate RESTORE on the
    # target's existing DACL chain (skipping soft-deleted ancestors for traverse)
    # and require CREATE_* on the chosen destination parent.
    masks = evaluate_effective_masks(
        subject,
        target_path,
        eval_time_utc=now,
        check_ancestor_traverse=check_traverse,
    )
    if not masks.allowed_traverse:
        return EvalDecision(
            allowed=False,
            reason=masks.denied_reason or "Missing TRAVERSE on ancestor.",
            step=masks.denied_step or "2_path_traverse",
            next_transition_at=masks.next_transition_at,
        )
    if not (masks.effective_mask & int(AtomicOp.RESTORE)):
        return EvalDecision(
            allowed=False,
            reason="Missing RESTORE permission on target.",
            step="4_deny_overrides"
            if (masks.effective_deny_mask & int(AtomicOp.RESTORE))
            else "4_default_deny",
            effective_allow_mask=masks.effective_allow_mask,
            effective_deny_mask=masks.effective_deny_mask,
            next_transition_at=masks.next_transition_at,
        )

    return evaluate_access(
        subject,
        paths[target_parent.id],
        dest_op,
        eval_time_utc=now,
        check_ancestor_traverse=check_traverse,
    )


def authorize_dacl_save(
    session: OrmSession,
    user: User,
    target: Document | Folder,
    proposed_policy: CompiledPolicy,
    *,
    eval_time_utc: datetime.datetime | None = None,
) -> SaveAuthzResult:
    """Evaluate CEP-0002 Section 5.2 WRITE_DACL + anti-lockout simulation."""
    if has_bypass_dacl(user):
        return SaveAuthzResult(
            authorized=True,
            reason="Actor holds global BYPASS_DACL capability.",
            self_lockout_warning=False,
        )

    now = eval_time_utc or datetime.datetime.now(datetime.UTC)
    path = load_ancestor_path(session, target)
    return authorize_policy_save(
        user_to_subject(user),
        path,
        proposed_policy,
        eval_time_utc=now,
        check_ancestor_traverse=should_check_ancestor_traverse(session, user),
    )

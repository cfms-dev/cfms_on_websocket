__all__ = [
    "DirectorySoftDeleteRootCheck",
    "authorize_create_on_parent",
    "authorize_dacl_read",
    "authorize_dacl_save",
    "authorize_directory_access_with_parent",
    "authorize_directory_soft_delete",
    "authorize_node_operation",
    "authorize_reparent",
    "authorize_restore",
    "authorize_soft_delete_descendants",
    "authorize_write_dacl_and_load_path",
    "check_directory_soft_delete_root",
    "evaluate_node_effective_masks",
    "has_bypass_dacl",
    "load_ancestor_path",
    "load_ancestor_paths_for_nodes",
    "node_to_object_state",
    "node_to_object_type",
    "should_check_ancestor_traverse",
    "simulate_dacl_save_lockout",
    "user_to_subject",
    "would_self_lockout_on_create",
]

import datetime
from collections.abc import Sequence
from dataclasses import dataclass, field
from itertools import batched
from typing import Any, Protocol

from cacl_compiler import AtomicOp, CompiledPolicy, ObjectType
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
from include.domains.access.authorization.engine import (
    EffectiveMasksResult,
    EvalDecision,
    InheritedDaclState,
    NamespaceNode,
    ObjectState,
    SaveAuthzResult,
    Subject,
    SubtreeNode,
    authorize_policy_save,
    evaluate_access,
    evaluate_effective_masks,
    evaluate_path_masks,
    evaluate_reparent,
    evaluate_soft_delete_subtree,
    op_applies_to_object,
    op_applies_to_state,
)
from include.domains.access.authorization.storage import load_node_policies
from include.domains.access.permissions import Permissions

_ALL_OPS_MASK = (1 << len(AtomicOp)) - 1


class _SubtreeNodeLike(Protocol):
    @property
    def id(self) -> Any: ...
    @property
    def name(self) -> Any: ...
    @property
    def parent_id(self) -> Any: ...
    @property
    def type(self) -> Any: ...
    @property
    def status(self) -> Any: ...
    @property
    def inherit(self) -> Any: ...


@dataclass(frozen=True, slots=True)
class DirectorySoftDeleteRootCheck:
    allowed: bool
    needs_descendant_check: bool
    target_effective_mask: int = 0
    target_inherited: InheritedDaclState = field(default_factory=InheritedDaclState)
    check_ancestor_traverse: bool = True
    eval_time_utc: datetime.datetime | None = None


def has_bypass_dacl(user: User) -> bool:
    return Permissions.BYPASS_DACL in user.all_permissions


def user_to_subject(user: User) -> Subject:
    return Subject(
        user_id=user.id,
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
    exclude_expired_before: datetime.datetime | None = None,
    active_at_utc: datetime.datetime | None = None,
    canonicalize: bool = True,
) -> dict[str, list[NamespaceNode]]:
    """Bulk-load root-to-node NamespaceNode paths for a batch of targets."""
    if not targets:
        return {}

    target_ids = list(dict.fromkeys(t.id for t in targets))
    node_table = Node.__table__
    all_node_rows: dict[str, tuple[str, str, str | None, str, int, bool]] = {}

    for chunk in batched(target_ids, QUERY_CHUNK_SIZE):
        chunk_ids = list(chunk)
        anchor = select(
            node_table.c.id.label("id"),
            node_table.c.name.label("name"),
            node_table.c.parent_id.label("parent_id"),
            node_table.c.type.label("type"),
            node_table.c.status.label("status"),
            node_table.c.inherit.label("inherit"),
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
                parent_node.c.inherit,
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
                ancestors.c.inherit,
            ).distinct()
        ).all()
        for nid, name, parent_id, node_type, status, inherit_flag in rows:
            all_node_rows[nid] = (
                nid,
                name,
                parent_id,
                node_type,
                status,
                bool(inherit_flag),
            )

    # Ensure in-memory unflushed target state (e.g. newly created or modified nodes) is authoritative.
    for target in targets:
        all_node_rows[target.id] = (
            target.id,
            target.name,
            target.parent_id,
            target.type,
            int(target.status),
            bool(target.inherit),
        )

    preloaded_inherit = {nid: row[5] for nid, row in all_node_rows.items()}
    policies = load_node_policies(
        session,
        list(all_node_rows.keys()),
        include_deleted=True,
        preloaded_inherit=preloaded_inherit,
        exclude_expired_before=exclude_expired_before,
        active_at_utc=active_at_utc,
        canonicalize=canonicalize,
    )

    namespace_nodes: dict[str, NamespaceNode] = {}
    for nid, (
        _id,
        name,
        _parent_id,
        node_type,
        status,
        inherit_flag,
    ) in all_node_rows.items():
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
        policy = policies.get(nid, CompiledPolicy(inherit=inherit_flag, rules=()))
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
    exclude_expired_before: datetime.datetime | None = None,
    active_at_utc: datetime.datetime | None = None,
    canonicalize: bool = True,
) -> list[NamespaceNode]:
    return load_ancestor_paths_for_nodes(
        session,
        [target],
        include_deleted=include_deleted,
        exclude_expired_before=exclude_expired_before,
        active_at_utc=active_at_utc,
        canonicalize=canonicalize,
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
    path = load_ancestor_path(
        session,
        target,
        include_deleted=include_deleted,
        exclude_expired_before=now,
        canonicalize=False,
    )
    return evaluate_access(
        user_to_subject(user),
        path,
        operation,
        eval_time_utc=now,
        check_ancestor_traverse=should_check_ancestor_traverse(session, user),
    )


def evaluate_node_effective_masks(
    session: OrmSession,
    user: User,
    target: Document | Folder,
    *,
    include_deleted: bool = False,
    eval_time_utc: datetime.datetime | None = None,
) -> EffectiveMasksResult:
    """Compute effective masks for a target node in one DB pass."""
    if has_bypass_dacl(user):
        return EffectiveMasksResult(
            allowed_traverse=True,
            effective_allow_mask=_ALL_OPS_MASK,
            effective_deny_mask=0,
            effective_mask=_ALL_OPS_MASK,
        )

    now = eval_time_utc or datetime.datetime.now(datetime.UTC)
    path = load_ancestor_path(
        session,
        target,
        include_deleted=include_deleted,
        exclude_expired_before=now,
        canonicalize=False,
    )
    return evaluate_effective_masks(
        user_to_subject(user),
        path,
        eval_time_utc=now,
        check_ancestor_traverse=should_check_ancestor_traverse(session, user),
    )


def authorize_directory_access_with_parent(
    session: OrmSession,
    user: User,
    directory: Folder,
    operation: AtomicOp,
    *,
    eval_time_utc: datetime.datetime | None = None,
) -> tuple[bool, str | None]:
    """Authorize directory access and compute visible parent_id in a single DB pass."""
    if _check_step1_invariants(directory, operation) is not None:
        return False, None

    if has_bypass_dacl(user):
        return True, directory.parent_id

    now = eval_time_utc or datetime.datetime.now(datetime.UTC)
    path = load_ancestor_path(
        session,
        directory,
        exclude_expired_before=now,
        canonicalize=False,
    )
    path_masks = evaluate_path_masks(
        user_to_subject(user),
        path,
        eval_time_utc=now,
        check_ancestor_traverse=should_check_ancestor_traverse(session, user),
    )
    if not path_masks.target.allowed_traverse or not (
        path_masks.target.effective_mask & int(operation)
    ):
        return False, None

    visible_parent_id = (
        directory.parent_id
        if (
            directory.parent_id is not None
            and path_masks.parent_state is ObjectState.NORMAL
            and bool(path_masks.parent_effective_mask & int(AtomicOp.LIST_DIRECTORY))
        )
        else None
    )
    return True, visible_parent_id


def authorize_dacl_read(
    session: OrmSession,
    user: User,
    target: Document | Folder,
    *,
    eval_time_utc: datetime.datetime | None = None,
) -> tuple[bool, CompiledPolicy | None]:
    """Authorize READ_DACL and return the target's canonical CompiledPolicy in one DB pass."""
    if _check_step1_invariants(target, AtomicOp.READ_DACL) is not None:
        return False, None

    if has_bypass_dacl(user):
        policy = load_node_policies(
            session,
            [target.id],
            preloaded_inherit={target.id: bool(target.inherit)},
            canonicalize=True,
        )[target.id]
        return True, policy

    now = eval_time_utc or datetime.datetime.now(datetime.UTC)
    path = load_ancestor_path(
        session,
        target,
        exclude_expired_before=None,
        canonicalize=True,
    )
    decision = evaluate_access(
        user_to_subject(user),
        path,
        AtomicOp.READ_DACL,
        eval_time_utc=now,
        check_ancestor_traverse=should_check_ancestor_traverse(session, user),
    )
    if not decision.allowed:
        return False, None
    return True, path[-1].policy


def authorize_write_dacl_and_load_path(
    session: OrmSession,
    user: User,
    target: Document | Folder,
    *,
    eval_time_utc: datetime.datetime | None = None,
) -> tuple[bool, list[NamespaceNode] | None, bool]:
    """Authorize WRITE_DACL up front and return the loaded path for post-compile lockout checks."""
    if _check_step1_invariants(target, AtomicOp.WRITE_DACL) is not None:
        return False, None, False

    if has_bypass_dacl(user):
        return True, None, False

    now = eval_time_utc or datetime.datetime.now(datetime.UTC)
    path = load_ancestor_path(
        session,
        target,
        exclude_expired_before=now,
        canonicalize=False,
    )
    check_traverse = should_check_ancestor_traverse(session, user)
    decision = evaluate_access(
        user_to_subject(user),
        path,
        AtomicOp.WRITE_DACL,
        eval_time_utc=now,
        check_ancestor_traverse=check_traverse,
    )
    if not decision.allowed:
        return False, None, check_traverse
    return True, path, check_traverse


def simulate_dacl_save_lockout(
    user: User,
    current_path: list[NamespaceNode] | None,
    proposed_policy: CompiledPolicy,
    *,
    check_ancestor_traverse: bool,
    eval_time_utc: datetime.datetime | None = None,
) -> bool:
    """Return True if saving proposed_policy would revoke WRITE_DACL, using a preloaded path."""
    if current_path is None or has_bypass_dacl(user):
        return False

    now = eval_time_utc or datetime.datetime.now(datetime.UTC)
    target = current_path[-1]
    simulated_target = NamespaceNode(
        node_id=target.node_id,
        name=target.name,
        object_type=target.object_type,
        state=target.state,
        policy=proposed_policy,
    )
    post_check = evaluate_access(
        user_to_subject(user),
        current_path[:-1] + [simulated_target],
        AtomicOp.WRITE_DACL,
        eval_time_utc=now,
        check_ancestor_traverse=check_ancestor_traverse,
    )
    return not post_check.allowed


def authorize_create_on_parent(
    session: OrmSession,
    user: User,
    parent: Folder,
    operation: AtomicOp,
    *,
    require_write_dacl: bool = False,
    eval_time_utc: datetime.datetime | None = None,
) -> tuple[bool, bool, list[NamespaceNode] | None, bool]:
    """Check CREATE_* (and optional WRITE_DACL) on parent in one DB pass."""
    if _check_step1_invariants(parent, operation) is not None:
        return False, False, None, False
    if (
        require_write_dacl
        and _check_step1_invariants(parent, AtomicOp.WRITE_DACL) is not None
    ):
        return True, False, None, False

    if has_bypass_dacl(user):
        return True, True, None, False

    now = eval_time_utc or datetime.datetime.now(datetime.UTC)
    parent_path = load_ancestor_path(
        session,
        parent,
        exclude_expired_before=now,
        canonicalize=False,
    )
    check_traverse = should_check_ancestor_traverse(session, user)
    masks = evaluate_effective_masks(
        user_to_subject(user),
        parent_path,
        eval_time_utc=now,
        check_ancestor_traverse=check_traverse,
    )
    if not masks.allowed_traverse:
        return False, False, None, check_traverse

    can_create = bool(masks.effective_mask & int(operation))
    can_write_dacl = (
        bool(masks.effective_mask & int(AtomicOp.WRITE_DACL))
        if require_write_dacl
        else True
    )
    return can_create, can_write_dacl, parent_path, check_traverse


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
    paths = load_ancestor_paths_for_nodes(
        session,
        [source, dest_parent],
        exclude_expired_before=now,
        canonicalize=False,
    )
    return evaluate_reparent(
        user_to_subject(user),
        paths[source.id],
        paths[dest_parent.id],
        eval_time_utc=now,
        check_ancestor_traverse=should_check_ancestor_traverse(session, user),
    )


def check_directory_soft_delete_root(
    session: OrmSession,
    user: User,
    target: Folder,
    *,
    eval_time_utc: datetime.datetime | None = None,
) -> DirectorySoftDeleteRootCheck:
    """Authorize DELETE and DIRECTORY_DELETE_CHILD on target before scanning any subtree."""
    if _check_step1_invariants(target, AtomicOp.DELETE) is not None:
        return DirectorySoftDeleteRootCheck(allowed=False, needs_descendant_check=False)

    if has_bypass_dacl(user):
        return DirectorySoftDeleteRootCheck(allowed=True, needs_descendant_check=False)

    now = eval_time_utc or datetime.datetime.now(datetime.UTC)
    path = load_ancestor_path(
        session,
        target,
        exclude_expired_before=now,
        canonicalize=False,
    )
    check_traverse = should_check_ancestor_traverse(session, user)
    path_masks = evaluate_path_masks(
        user_to_subject(user),
        path,
        eval_time_utc=now,
        check_ancestor_traverse=check_traverse,
    )
    if not path_masks.target.allowed_traverse or not (
        path_masks.target.effective_mask & int(AtomicOp.DELETE)
    ):
        return DirectorySoftDeleteRootCheck(allowed=False, needs_descendant_check=False)

    if path_masks.target.effective_mask & int(AtomicOp.DIRECTORY_DELETE_CHILD):
        return DirectorySoftDeleteRootCheck(allowed=True, needs_descendant_check=False)

    return DirectorySoftDeleteRootCheck(
        allowed=True,
        needs_descendant_check=True,
        target_effective_mask=path_masks.target.effective_mask,
        target_inherited=path_masks.target_inherited,
        check_ancestor_traverse=check_traverse,
        eval_time_utc=now,
    )


def authorize_soft_delete_descendants(
    session: OrmSession,
    user: User,
    target_id: str,
    descendant_rows: Sequence[_SubtreeNodeLike],
    root_check: DirectorySoftDeleteRootCheck,
) -> EvalDecision:
    """Load only descendant DACLs (0 ancestor CTEs) and verify DELETE in O(N * R)."""
    if not root_check.allowed:
        return EvalDecision(
            allowed=False,
            reason="DELETE on target failed.",
            step="5_composite_delete_target",
        )
    if not root_check.needs_descendant_check or not descendant_rows:
        return EvalDecision(
            allowed=True,
            reason="Subtree delete authorized without per-descendant checks.",
            step="5_composite_allowed",
        )

    now = root_check.eval_time_utc or datetime.datetime.now(datetime.UTC)
    preloaded_inherit = {row.id: bool(row.inherit) for row in descendant_rows}
    policies = load_node_policies(
        session,
        list(preloaded_inherit.keys()),
        include_deleted=False,
        preloaded_inherit=preloaded_inherit,
        exclude_expired_before=now,
        canonicalize=False,
    )

    subtree_nodes = [
        SubtreeNode(
            node_id=row.id,
            parent_id=row.parent_id or target_id,
            name=row.name,
            object_type=(
                ObjectType.DOCUMENT
                if row.type == NodeType.DOCUMENT.value
                else ObjectType.DIRECTORY
            ),
            state=(
                ObjectState.SOFT_DELETED
                if int(row.status) == EntityStatus.DELETED.value
                else ObjectState.NORMAL
            ),
            policy=policies.get(
                row.id, CompiledPolicy(inherit=bool(row.inherit), rules=())
            ),
        )
        for row in descendant_rows
    ]
    return evaluate_soft_delete_subtree(
        user_to_subject(user),
        target_id,
        root_check.target_effective_mask,
        root_check.target_inherited,
        subtree_nodes,
        eval_time_utc=now,
        check_ancestor_traverse=root_check.check_ancestor_traverse,
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
    root_check = check_directory_soft_delete_root(
        session, user, target, eval_time_utc=eval_time_utc
    )
    if not root_check.allowed:
        return EvalDecision(
            allowed=False,
            reason="DELETE on target failed.",
            step="5_composite_delete_target",
        )
    return authorize_soft_delete_descendants(
        session, user, target.id, descendants, root_check
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
        session,
        [target, target_parent],
        include_deleted=True,
        exclude_expired_before=now,
        canonicalize=False,
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
    path = load_ancestor_path(
        session,
        target,
        exclude_expired_before=now,
        canonicalize=False,
    )
    return authorize_policy_save(
        user_to_subject(user),
        path,
        proposed_policy,
        eval_time_utc=now,
        check_ancestor_traverse=should_check_ancestor_traverse(session, user),
    )


def would_self_lockout_on_create(
    session: OrmSession,
    user: User,
    parent: Folder,
    object_type: ObjectType,
    name: str,
    proposed_policy: CompiledPolicy,
    *,
    eval_time_utc: datetime.datetime | None = None,
    parent_path: list[NamespaceNode] | None = None,
    check_ancestor_traverse: bool | None = None,
) -> bool:
    """Return True if saving proposed_policy on a newly created child would revoke the actor's WRITE_DACL."""
    if has_bypass_dacl(user):
        return False

    now = eval_time_utc or datetime.datetime.now(datetime.UTC)
    resolved_path = (
        parent_path
        if parent_path is not None
        else load_ancestor_path(
            session,
            parent,
            exclude_expired_before=now,
            canonicalize=False,
        )
    )
    check_traverse = (
        check_ancestor_traverse
        if check_ancestor_traverse is not None
        else should_check_ancestor_traverse(session, user)
    )
    simulated_node = NamespaceNode(
        node_id="__pending__",
        name=name,
        object_type=object_type,
        state=ObjectState.NORMAL,
        policy=proposed_policy,
    )
    post_check = evaluate_access(
        user_to_subject(user),
        [*resolved_path, simulated_node],
        AtomicOp.WRITE_DACL,
        eval_time_utc=now,
        check_ancestor_traverse=check_traverse,
    )
    return not post_check.allowed

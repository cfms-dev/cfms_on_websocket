__all__ = [
    "CreateAuthzCheck",
    "DaclReadAuthzResult",
    "DaclWriteAuthzCheck",
    "DirectoryAccessResult",
    "DirectorySoftDeleteRootCheck",
    "DirectorySubtreeOpRootCheck",
    "ListingMaskTarget",
    "authorize_create_on_parent",
    "authorize_dacl_read",
    "authorize_directory_access",
    "authorize_directory_reparent",
    "authorize_node_access_with_mask",
    "authorize_node_operation",
    "authorize_purge_descendants",
    "authorize_reparent",
    "authorize_restore",
    "authorize_restore_descendants",
    "authorize_soft_delete_descendants",
    "authorize_write_dacl_and_load_path",
    "check_directory_purge_root",
    "check_directory_restore_root",
    "check_directory_soft_delete_root",
    "compute_created_node_effective_mask",
    "compute_listing_item_effective_masks",
    "compute_post_save_dacl_effective_mask",
    "evaluate_node_effective_masks",
    "global_gate_ops_mask",
    "global_gate_ops_mask_from_perms",
    "has_bypass_dacl",
    "load_ancestor_paths_for_nodes",
    "node_to_object_state",
    "node_to_object_type",
    "project_effective_mask",
    "should_check_ancestor_traverse",
    "simulate_dacl_save_lockout",
    "user_to_subject",
    "would_self_lockout_on_create",
]

import datetime
import operator
from collections.abc import Callable, Collection, Mapping, Sequence
from dataclasses import dataclass, field
from functools import reduce
from itertools import batched
from typing import Any, Protocol

from cacl_compiler import AtomicOp, CompiledPolicy, ObjectType
from sqlalchemy import select
from sqlalchemy.orm import Session as OrmSession

from include.config.constants import (
    MAX_HIERARCHY_DEPTH,
    QUERY_CHUNK_SIZE,
    ROOT_DIRECTORY_ID,
)
from include.config.options import BYPASS_TRAVERSE_CHECKING_OPTION, read_option
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
    Subject,
    SubtreeNode,
    applicable_ops_mask,
    check_op_applicability,
    evaluate_access,
    evaluate_child_effective_mask,
    evaluate_effective_masks,
    evaluate_path_masks,
    evaluate_purge_subtree,
    evaluate_reparent,
    evaluate_restore,
    evaluate_restore_subtree,
    evaluate_soft_delete_subtree,
    simulate_policy_save_lockout,
)
from include.domains.access.authorization.storage import (
    build_ancestor_chain_cte,
    load_node_policies,
)
from include.domains.access.permissions import Permissions

_ALL_OPS_MASK = int(reduce(operator.or_, AtomicOp, 0))


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
class _AncestorNodeRow:
    id: str
    name: str
    parent_id: str | None
    node_type: str
    status: int
    inherit: bool


@dataclass(frozen=True, slots=True)
class CreateAuthzCheck:
    can_create: bool
    can_write_dacl: bool
    parent_path: list[NamespaceNode] | None = None
    check_ancestor_traverse: bool = False
    eval_time_utc: datetime.datetime | None = None


@dataclass(frozen=True, slots=True)
class DaclWriteAuthzCheck:
    authorized: bool
    reason: str
    current_path: list[NamespaceNode] | None = None
    check_ancestor_traverse: bool = False
    eval_time_utc: datetime.datetime | None = None


@dataclass(frozen=True, slots=True)
class DaclReadAuthzResult:
    allowed: bool
    policy: CompiledPolicy | None = None
    effective_mask: int = 0


@dataclass(frozen=True, slots=True)
class DirectoryAccessResult:
    allowed: bool
    visible_parent_id: str | None = None
    effective_mask: int = 0
    target_inherited: InheritedDaclState = field(default_factory=InheritedDaclState)
    children_traversable: bool = False
    bypass_dacl: bool = False
    eval_time_utc: datetime.datetime | None = None


@dataclass(frozen=True, slots=True)
class ListingMaskTarget:
    node_id: str
    object_type: ObjectType
    state: ObjectState
    inherit: bool


@dataclass(frozen=True, slots=True)
class DirectorySoftDeleteRootCheck:
    allowed: bool
    needs_descendant_check: bool
    target_effective_mask: int = 0
    target_inherited: InheritedDaclState = field(default_factory=InheritedDaclState)
    check_ancestor_traverse: bool = True
    eval_time_utc: datetime.datetime | None = None


@dataclass(frozen=True, slots=True)
class DirectorySubtreeOpRootCheck:
    allowed: bool
    bypass_dacl: bool = False
    target_inherited: InheritedDaclState = field(default_factory=InheritedDaclState)
    dest_ancestor_ids: frozenset[str] = frozenset()
    eval_time_utc: datetime.datetime | None = None


def has_bypass_dacl(user: User) -> bool:
    return Permissions.BYPASS_DACL in user.all_permissions


def global_gate_ops_mask_from_perms(perms: Collection[str]) -> int:
    """Return the 21-bit mask of AtomicOps not blocked by global permission gates."""
    mask = _ALL_OPS_MASK
    if Permissions.PURGE not in perms:
        mask &= ~int(AtomicOp.PURGE)
    if Permissions.DELETE_REVISION not in perms:
        mask &= ~int(AtomicOp.DELETE_REVISION)
    return mask


def global_gate_ops_mask(user: User) -> int:
    """Return the 21-bit mask of AtomicOps permitted by user's global permission gates."""
    return global_gate_ops_mask_from_perms(user.all_permissions)


def project_effective_mask(
    raw_mask: int,
    *,
    object_type: ObjectType,
    state: ObjectState,
    global_mask: int,
    is_root: bool = False,
) -> int:
    """Clamp a raw CACL effective mask by target/state/root invariants and global gates."""
    return (
        raw_mask
        & applicable_ops_mask(object_type, state, is_root=is_root)
        & global_mask
    )


def user_to_subject(user: User) -> Subject:
    return Subject(
        user_id=user.id,
        groups=frozenset(user.all_groups),
        perms=frozenset(str(perm) for perm in user.all_permissions),
    )


def should_check_ancestor_traverse(session: OrmSession, user: User) -> bool:
    if Permissions.BYPASS_TRAVERSE_CHECKING in user.all_permissions:
        return False
    bypass_option = read_option(
        session, "access", BYPASS_TRAVERSE_CHECKING_OPTION
    ).value
    return not bool(bypass_option)


def node_to_object_type(node: Document | Folder | Node) -> ObjectType:
    if isinstance(node, Document) or node.type == NodeType.DOCUMENT.value:
        return ObjectType.DOCUMENT
    return ObjectType.DIRECTORY


def node_to_object_state(node: Document | Folder | Node) -> ObjectState:
    if node.status == EntityStatus.DELETED:
        return ObjectState.SOFT_DELETED
    return ObjectState.NORMAL


def _fetch_ancestor_node_rows(
    session: OrmSession,
    target_ids: Sequence[str],
) -> dict[str, _AncestorNodeRow]:
    all_node_rows: dict[str, _AncestorNodeRow] = {}

    for chunk in batched(target_ids, QUERY_CHUNK_SIZE):
        ancestors = build_ancestor_chain_cte(
            list(chunk),
            cte_name="cacl_ancestor_chain",
            parent_alias_name="cacl_parent_node",
            column_names=("id", "name", "parent_id", "type", "status", "inherit"),
            max_depth=MAX_HIERARCHY_DEPTH,
        )

        rows = (
            session.execute(
                select(
                    ancestors.c.id.label("id"),
                    ancestors.c.name.label("name"),
                    ancestors.c.parent_id.label("parent_id"),
                    ancestors.c.type.label("type"),
                    ancestors.c.status.label("status"),
                    ancestors.c.inherit.label("inherit"),
                ).distinct()
            )
            .mappings()
            .all()
        )
        for row in rows:
            nid: str = row["id"]
            all_node_rows[nid] = _AncestorNodeRow(
                id=nid,
                name=row["name"],
                parent_id=row["parent_id"],
                node_type=row["type"],
                status=int(row["status"]),
                inherit=bool(row["inherit"]),
            )
    return all_node_rows


def _assemble_namespace_chains(
    targets: Sequence[Document | Folder],
    all_node_rows: Mapping[str, _AncestorNodeRow],
    policies: Mapping[str, CompiledPolicy],
) -> dict[str, list[NamespaceNode]]:
    namespace_nodes: dict[str, NamespaceNode] = {}
    for nid, row in all_node_rows.items():
        obj_type = (
            ObjectType.DOCUMENT
            if row.node_type == NodeType.DOCUMENT.value
            else ObjectType.DIRECTORY
        )
        obj_state = (
            ObjectState.SOFT_DELETED
            if row.status == EntityStatus.DELETED.value
            else ObjectState.NORMAL
        )
        policy = policies.get(nid, CompiledPolicy(inherit=row.inherit, rules=()))
        namespace_nodes[nid] = NamespaceNode(
            node_id=nid,
            name=row.name,
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
                raise RuntimeError(
                    f"Incomplete ancestor chain for node {target.id!r}: "
                    f"missing ancestor {curr_id!r}"
                )
            chain.append(namespace_nodes[curr_id])
            curr_id = row.parent_id
        chain.reverse()
        if not chain or chain[0].node_id != ROOT_DIRECTORY_ID:
            raise RuntimeError(
                f"Incomplete ancestor chain for node {target.id!r}: "
                f"chain is not rooted at {ROOT_DIRECTORY_ID!r}"
            )
        result[target.id] = chain
    return result


def load_ancestor_paths_for_nodes(
    session: OrmSession,
    targets: Sequence[Document | Folder],
    *,
    exclude_expired_before: datetime.datetime | None = None,
    active_at_utc: datetime.datetime | None = None,
    canonicalize: bool = True,
) -> dict[str, list[NamespaceNode]]:
    """Bulk-load root-to-node NamespaceNode paths (including soft-deleted ancestors)."""
    if not targets:
        return {}

    target_ids = list(dict.fromkeys(t.id for t in targets))
    all_node_rows = _fetch_ancestor_node_rows(session, target_ids)

    # Ensure in-memory unflushed target state (e.g. newly created or modified nodes) is authoritative.
    for target in targets:
        all_node_rows[target.id] = _AncestorNodeRow(
            id=target.id,
            name=target.name,
            parent_id=target.parent_id,
            node_type=target.type,
            status=int(target.status),
            inherit=bool(target.inherit),
        )

    preloaded_inherit = {nid: row.inherit for nid, row in all_node_rows.items()}
    policies = load_node_policies(
        session,
        list(all_node_rows.keys()),
        include_deleted=True,
        preloaded_inherit=preloaded_inherit,
        exclude_expired_before=exclude_expired_before,
        active_at_utc=active_at_utc,
        canonicalize=canonicalize,
    )
    return _assemble_namespace_chains(targets, all_node_rows, policies)


def _load_ancestor_path(
    session: OrmSession,
    target: Document | Folder,
    *,
    exclude_expired_before: datetime.datetime | None = None,
    active_at_utc: datetime.datetime | None = None,
    canonicalize: bool = True,
) -> list[NamespaceNode]:
    return load_ancestor_paths_for_nodes(
        session,
        [target],
        exclude_expired_before=exclude_expired_before,
        active_at_utc=active_at_utc,
        canonicalize=canonicalize,
    )[target.id]


def _check_step1_invariants(
    target: Document | Folder,
    operation: AtomicOp,
) -> EvalDecision | None:
    return check_op_applicability(
        operation, node_to_object_type(target), node_to_object_state(target)
    )


def authorize_node_operation(
    session: OrmSession,
    user: User,
    target: Document | Folder,
    operation: AtomicOp,
    *,
    eval_time_utc: datetime.datetime | None = None,
    collect_traces: bool = False,
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
    path = _load_ancestor_path(
        session,
        target,
        exclude_expired_before=now,
        canonicalize=False,
    )
    return evaluate_access(
        user_to_subject(user),
        path,
        operation,
        eval_time_utc=now,
        check_ancestor_traverse=should_check_ancestor_traverse(session, user),
        collect_traces=collect_traces,
    )


def evaluate_node_effective_masks(
    session: OrmSession,
    user: User,
    target: Document | Folder,
    *,
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
    path = _load_ancestor_path(
        session,
        target,
        exclude_expired_before=now,
        canonicalize=False,
    )
    return evaluate_effective_masks(
        user_to_subject(user),
        path,
        eval_time_utc=now,
        check_ancestor_traverse=should_check_ancestor_traverse(session, user),
    )


def authorize_node_access_with_mask(
    session: OrmSession,
    user: User,
    target: Document | Folder,
    operation: AtomicOp,
    *,
    eval_time_utc: datetime.datetime | None = None,
) -> tuple[bool, int]:
    """Authorize a single operation on target and return its projected effective mask."""
    if _check_step1_invariants(target, operation) is not None:
        return False, 0

    obj_type = node_to_object_type(target)
    obj_state = node_to_object_state(target)
    is_root = target.id == ROOT_DIRECTORY_ID
    global_mask = global_gate_ops_mask(user)

    if has_bypass_dacl(user):
        return True, project_effective_mask(
            _ALL_OPS_MASK,
            object_type=obj_type,
            state=obj_state,
            global_mask=global_mask,
            is_root=is_root,
        )

    now = eval_time_utc or datetime.datetime.now(datetime.UTC)
    path = _load_ancestor_path(
        session,
        target,
        active_at_utc=now,
        canonicalize=False,
    )
    masks = evaluate_effective_masks(
        user_to_subject(user),
        path,
        eval_time_utc=now,
        check_ancestor_traverse=should_check_ancestor_traverse(session, user),
    )
    if not masks.allowed_traverse or not (masks.effective_mask & int(operation)):
        return False, 0
    return True, project_effective_mask(
        masks.effective_mask,
        object_type=obj_type,
        state=obj_state,
        global_mask=global_mask,
        is_root=is_root,
    )


def authorize_directory_access(
    session: OrmSession,
    user: User,
    directory: Folder,
    operation: AtomicOp,
    *,
    include_visible_parent: bool = True,
    eval_time_utc: datetime.datetime | None = None,
) -> DirectoryAccessResult:
    """Authorize directory access, compute visible parent_id, projected mask, and child context."""
    if _check_step1_invariants(directory, operation) is not None:
        return DirectoryAccessResult(allowed=False)

    dir_state = node_to_object_state(directory)
    is_root = directory.id == ROOT_DIRECTORY_ID
    global_mask = global_gate_ops_mask(user)

    if has_bypass_dacl(user):
        return DirectoryAccessResult(
            allowed=True,
            visible_parent_id=directory.parent_id if include_visible_parent else None,
            effective_mask=project_effective_mask(
                _ALL_OPS_MASK,
                object_type=ObjectType.DIRECTORY,
                state=dir_state,
                global_mask=global_mask,
                is_root=is_root,
            ),
            children_traversable=True,
            bypass_dacl=True,
            eval_time_utc=eval_time_utc,
        )

    now = eval_time_utc or datetime.datetime.now(datetime.UTC)
    path = _load_ancestor_path(
        session,
        directory,
        active_at_utc=now,
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
        path_masks.target.effective_mask & int(operation)
    ):
        return DirectoryAccessResult(allowed=False)

    visible_parent_id = (
        directory.parent_id
        if (
            include_visible_parent
            and directory.parent_id is not None
            and path_masks.parent_state is ObjectState.NORMAL
            and bool(path_masks.parent_effective_mask & int(AtomicOp.LIST_DIRECTORY))
        )
        else None
    )
    children_traversable = (
        not check_traverse
        or dir_state is ObjectState.SOFT_DELETED
        or bool(path_masks.target.effective_mask & int(AtomicOp.TRAVERSE))
    )
    return DirectoryAccessResult(
        allowed=True,
        visible_parent_id=visible_parent_id,
        effective_mask=project_effective_mask(
            path_masks.target.effective_mask,
            object_type=ObjectType.DIRECTORY,
            state=dir_state,
            global_mask=global_mask,
            is_root=is_root,
        ),
        target_inherited=path_masks.target_inherited,
        children_traversable=children_traversable,
        bypass_dacl=False,
        eval_time_utc=now,
    )


def compute_listing_item_effective_masks(
    session: OrmSession,
    user: User,
    parent_access: DirectoryAccessResult,
    targets: Sequence[ListingMaskTarget],
    *,
    include_deleted: bool = False,
) -> dict[str, int]:
    """Compute projected effective masks for direct children of an authorized folder."""
    if not targets:
        return {}

    global_mask = global_gate_ops_mask(user)
    if parent_access.bypass_dacl:
        return {
            target.node_id: project_effective_mask(
                _ALL_OPS_MASK,
                object_type=target.object_type,
                state=target.state,
                global_mask=global_mask,
            )
            for target in targets
        }

    if not parent_access.children_traversable:
        return {target.node_id: 0 for target in targets}

    now = parent_access.eval_time_utc or datetime.datetime.now(datetime.UTC)
    preloaded_inherit = {target.node_id: target.inherit for target in targets}
    policies = load_node_policies(
        session,
        list(preloaded_inherit.keys()),
        include_deleted=include_deleted,
        preloaded_inherit=preloaded_inherit,
        active_at_utc=now,
        canonicalize=False,
    )
    subject = user_to_subject(user)
    inherited = parent_access.target_inherited
    return {
        target.node_id: project_effective_mask(
            evaluate_child_effective_mask(
                subject,
                policies.get(
                    target.node_id, CompiledPolicy(inherit=target.inherit, rules=())
                ),
                target.object_type,
                inherited,
                now,
            ),
            object_type=target.object_type,
            state=target.state,
            global_mask=global_mask,
        )
        for target in targets
    }


def authorize_dacl_read(
    session: OrmSession,
    user: User,
    target: Document | Folder,
    *,
    eval_time_utc: datetime.datetime | None = None,
) -> DaclReadAuthzResult:
    """Authorize READ_DACL and return the target's canonical CompiledPolicy and projected mask."""
    if _check_step1_invariants(target, AtomicOp.READ_DACL) is not None:
        return DaclReadAuthzResult(allowed=False)

    obj_type = node_to_object_type(target)
    obj_state = node_to_object_state(target)
    is_root = target.id == ROOT_DIRECTORY_ID
    global_mask = global_gate_ops_mask(user)

    if has_bypass_dacl(user):
        policy = load_node_policies(
            session,
            [target.id],
            preloaded_inherit={target.id: bool(target.inherit)},
            canonicalize=True,
        )[target.id]
        return DaclReadAuthzResult(
            allowed=True,
            policy=policy,
            effective_mask=project_effective_mask(
                _ALL_OPS_MASK,
                object_type=obj_type,
                state=obj_state,
                global_mask=global_mask,
                is_root=is_root,
            ),
        )

    now = eval_time_utc or datetime.datetime.now(datetime.UTC)
    path = _load_ancestor_path(
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
        collect_traces=False,
    )
    if not decision.allowed:
        return DaclReadAuthzResult(allowed=False)
    raw_mask = decision.effective_allow_mask & ~decision.effective_deny_mask
    return DaclReadAuthzResult(
        allowed=True,
        policy=path[-1].policy,
        effective_mask=project_effective_mask(
            raw_mask,
            object_type=obj_type,
            state=obj_state,
            global_mask=global_mask,
            is_root=is_root,
        ),
    )


def authorize_write_dacl_and_load_path(
    session: OrmSession,
    user: User,
    target: Document | Folder,
    *,
    eval_time_utc: datetime.datetime | None = None,
) -> DaclWriteAuthzCheck:
    """Authorize WRITE_DACL up front and return the loaded path for post-compile lockout checks."""
    step1_denial = _check_step1_invariants(target, AtomicOp.WRITE_DACL)
    if step1_denial is not None:
        return DaclWriteAuthzCheck(
            authorized=False,
            reason=f"Missing WRITE_DACL: {step1_denial.reason}",
        )

    if has_bypass_dacl(user):
        return DaclWriteAuthzCheck(
            authorized=True,
            reason="Actor holds global BYPASS_DACL capability.",
        )

    now = eval_time_utc or datetime.datetime.now(datetime.UTC)
    path = _load_ancestor_path(
        session,
        target,
        active_at_utc=now,
        canonicalize=False,
    )
    check_traverse = should_check_ancestor_traverse(session, user)
    decision = evaluate_access(
        user_to_subject(user),
        path,
        AtomicOp.WRITE_DACL,
        eval_time_utc=now,
        check_ancestor_traverse=check_traverse,
        collect_traces=False,
    )
    if not decision.allowed:
        return DaclWriteAuthzCheck(
            authorized=False,
            reason=f"Missing WRITE_DACL: {decision.reason}",
            check_ancestor_traverse=check_traverse,
            eval_time_utc=now,
        )
    return DaclWriteAuthzCheck(
        authorized=True,
        reason="Actor holds WRITE_DACL.",
        current_path=path,
        check_ancestor_traverse=check_traverse,
        eval_time_utc=now,
    )


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

    return simulate_policy_save_lockout(
        user_to_subject(user),
        current_path,
        proposed_policy,
        eval_time_utc=eval_time_utc,
        check_ancestor_traverse=check_ancestor_traverse,
    )


def compute_post_save_dacl_effective_mask(
    user: User,
    target: Document | Folder,
    write_check: DaclWriteAuthzCheck,
    saved_policy: CompiledPolicy,
) -> int:
    """Compute the projected effective mask for target immediately after saving saved_policy."""
    obj_type = node_to_object_type(target)
    obj_state = node_to_object_state(target)
    is_root = target.id == ROOT_DIRECTORY_ID
    global_mask = global_gate_ops_mask(user)

    if write_check.current_path is None or has_bypass_dacl(user):
        return project_effective_mask(
            _ALL_OPS_MASK,
            object_type=obj_type,
            state=obj_state,
            global_mask=global_mask,
            is_root=is_root,
        )

    current_target = write_check.current_path[-1]
    updated_target = NamespaceNode(
        node_id=current_target.node_id,
        name=current_target.name,
        object_type=current_target.object_type,
        state=current_target.state,
        policy=saved_policy,
    )
    masks = evaluate_effective_masks(
        user_to_subject(user),
        [*write_check.current_path[:-1], updated_target],
        eval_time_utc=write_check.eval_time_utc,
        check_ancestor_traverse=write_check.check_ancestor_traverse,
    )
    if not masks.allowed_traverse:
        return 0
    return project_effective_mask(
        masks.effective_mask,
        object_type=obj_type,
        state=obj_state,
        global_mask=global_mask,
        is_root=is_root,
    )


def compute_created_node_effective_mask(
    user: User,
    *,
    node_id: str,
    name: str,
    object_type: ObjectType,
    create_check: CreateAuthzCheck,
    initial_policy: CompiledPolicy | None = None,
) -> int:
    """Compute the projected effective mask for a newly created child using preloaded parent_path."""
    global_mask = global_gate_ops_mask(user)
    if create_check.parent_path is None or has_bypass_dacl(user):
        return project_effective_mask(
            _ALL_OPS_MASK,
            object_type=object_type,
            state=ObjectState.NORMAL,
            global_mask=global_mask,
        )

    child_policy = (
        initial_policy
        if initial_policy is not None
        else CompiledPolicy(inherit=True, rules=())
    )
    created_node = NamespaceNode(
        node_id=node_id,
        name=name,
        object_type=object_type,
        state=ObjectState.NORMAL,
        policy=child_policy,
    )
    masks = evaluate_effective_masks(
        user_to_subject(user),
        [*create_check.parent_path, created_node],
        eval_time_utc=create_check.eval_time_utc,
        check_ancestor_traverse=create_check.check_ancestor_traverse,
    )
    if not masks.allowed_traverse:
        return 0
    return project_effective_mask(
        masks.effective_mask,
        object_type=object_type,
        state=ObjectState.NORMAL,
        global_mask=global_mask,
    )


def authorize_create_on_parent(
    session: OrmSession,
    user: User,
    parent: Folder,
    operation: AtomicOp,
    *,
    require_write_dacl: bool = False,
    eval_time_utc: datetime.datetime | None = None,
) -> CreateAuthzCheck:
    """Check CREATE_* (and optional WRITE_DACL) on parent in one DB pass."""
    if _check_step1_invariants(parent, operation) is not None:
        return CreateAuthzCheck(can_create=False, can_write_dacl=False)
    if (
        require_write_dacl
        and _check_step1_invariants(parent, AtomicOp.WRITE_DACL) is not None
    ):
        return CreateAuthzCheck(can_create=False, can_write_dacl=False)

    if has_bypass_dacl(user):
        return CreateAuthzCheck(can_create=True, can_write_dacl=True)

    now = eval_time_utc or datetime.datetime.now(datetime.UTC)
    parent_path = _load_ancestor_path(
        session,
        parent,
        active_at_utc=now,
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
        return CreateAuthzCheck(
            can_create=False,
            can_write_dacl=False,
            check_ancestor_traverse=check_traverse,
            eval_time_utc=now,
        )

    can_create = bool(masks.effective_mask & int(operation))
    can_write_dacl = (
        bool(masks.effective_mask & int(AtomicOp.WRITE_DACL))
        if require_write_dacl
        else True
    )
    return CreateAuthzCheck(
        can_create=can_create,
        can_write_dacl=can_write_dacl,
        parent_path=parent_path,
        check_ancestor_traverse=check_traverse,
        eval_time_utc=now,
    )


def _authorize_reparent_impl(
    session: OrmSession,
    user: User,
    source: Document | Folder,
    dest_parent: Folder,
    *,
    eval_time_utc: datetime.datetime | None = None,
    load_dest_ancestors: bool = False,
) -> tuple[EvalDecision, frozenset[str]]:
    if has_bypass_dacl(user):
        src_step1 = _check_step1_invariants(source, AtomicOp.REPARENT)
        if src_step1 is not None:
            return src_step1, frozenset()
        dest_op = (
            AtomicOp.CREATE_DOCUMENT
            if isinstance(source, Document)
            else AtomicOp.CREATE_DIRECTORY
        )
        dst_step1 = _check_step1_invariants(dest_parent, dest_op)
        if dst_step1 is not None:
            return dst_step1, frozenset()
        dest_ancestors = (
            frozenset(_fetch_ancestor_node_rows(session, [dest_parent.id]).keys())
            if load_dest_ancestors
            else frozenset()
        )
        return (
            EvalDecision(
                allowed=True,
                reason="Allowed by global BYPASS_DACL capability.",
                step="0_bypass_dacl",
            ),
            dest_ancestors,
        )

    now = eval_time_utc or datetime.datetime.now(datetime.UTC)
    paths = load_ancestor_paths_for_nodes(
        session,
        [source, dest_parent],
        exclude_expired_before=now,
        canonicalize=False,
    )
    decision = evaluate_reparent(
        user_to_subject(user),
        paths[source.id],
        paths[dest_parent.id],
        eval_time_utc=now,
        check_ancestor_traverse=should_check_ancestor_traverse(session, user),
        collect_traces=False,
    )
    dest_ancestors = (
        frozenset(node.node_id for node in paths[dest_parent.id])
        if load_dest_ancestors
        else frozenset()
    )
    return decision, dest_ancestors


def authorize_reparent(
    session: OrmSession,
    user: User,
    source: Document | Folder,
    dest_parent: Folder,
    *,
    eval_time_utc: datetime.datetime | None = None,
) -> EvalDecision:
    """Evaluate CEP 2 Step 5 composite reparent (REPARENT on source + CREATE_* on dest)."""
    decision, _ = _authorize_reparent_impl(
        session,
        user,
        source,
        dest_parent,
        eval_time_utc=eval_time_utc,
        load_dest_ancestors=False,
    )
    return decision


def authorize_directory_reparent(
    session: OrmSession,
    user: User,
    source: Folder,
    dest_parent: Folder,
    *,
    eval_time_utc: datetime.datetime | None = None,
) -> tuple[EvalDecision, frozenset[str]]:
    """Evaluate reparent and return destination ancestor node IDs for cycle checks."""
    return _authorize_reparent_impl(
        session,
        user,
        source,
        dest_parent,
        eval_time_utc=eval_time_utc,
        load_dest_ancestors=True,
    )


def _build_subtree_nodes(
    descendant_rows: Sequence[_SubtreeNodeLike],
    target_id: str,
    policies: Mapping[str, CompiledPolicy],
) -> list[SubtreeNode]:
    return [
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
    path = _load_ancestor_path(
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
    subtree_nodes = _build_subtree_nodes(descendant_rows, target_id, policies)
    return evaluate_soft_delete_subtree(
        user_to_subject(user),
        target_id,
        root_check.target_effective_mask,
        root_check.target_inherited,
        subtree_nodes,
        eval_time_utc=now,
        check_ancestor_traverse=root_check.check_ancestor_traverse,
    )


def check_directory_purge_root(
    session: OrmSession,
    user: User,
    target: Folder,
    *,
    eval_time_utc: datetime.datetime | None = None,
) -> DirectorySubtreeOpRootCheck:
    """Authorize PURGE on target soft-deleted directory and capture inherited DACL state."""
    if _check_step1_invariants(target, AtomicOp.PURGE) is not None:
        return DirectorySubtreeOpRootCheck(allowed=False)

    if has_bypass_dacl(user):
        return DirectorySubtreeOpRootCheck(allowed=True, bypass_dacl=True)

    now = eval_time_utc or datetime.datetime.now(datetime.UTC)
    path = _load_ancestor_path(
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
        path_masks.target.effective_mask & int(AtomicOp.PURGE)
    ):
        return DirectorySubtreeOpRootCheck(allowed=False)

    return DirectorySubtreeOpRootCheck(
        allowed=True,
        target_inherited=path_masks.target_inherited,
        eval_time_utc=now,
    )


def check_directory_restore_root(
    session: OrmSession,
    user: User,
    target: Folder,
    target_parent: Folder,
    *,
    eval_time_utc: datetime.datetime | None = None,
) -> DirectorySubtreeOpRootCheck:
    """Authorize RESTORE on target directory (+ CREATE_DIRECTORY on dest) and capture state."""
    if (
        _check_step1_invariants(target, AtomicOp.RESTORE) is not None
        or target_parent.status != EntityStatus.OK
    ):
        return DirectorySubtreeOpRootCheck(allowed=False)

    if has_bypass_dacl(user):
        dest_ancestors = frozenset(
            _fetch_ancestor_node_rows(session, [target_parent.id]).keys()
        )
        return DirectorySubtreeOpRootCheck(
            allowed=True,
            bypass_dacl=True,
            dest_ancestor_ids=dest_ancestors,
        )

    reparenting = (target.parent_id or ROOT_DIRECTORY_ID) != target_parent.id
    now = eval_time_utc or datetime.datetime.now(datetime.UTC)
    paths = load_ancestor_paths_for_nodes(
        session,
        [target, target_parent],
        exclude_expired_before=now,
        canonicalize=False,
    )
    subject = user_to_subject(user)
    check_traverse = should_check_ancestor_traverse(session, user)
    decision = evaluate_restore(
        subject,
        paths[target.id],
        paths[target_parent.id],
        reparenting=reparenting,
        eval_time_utc=now,
        check_ancestor_traverse=check_traverse,
        collect_traces=False,
    )
    if not decision.allowed:
        return DirectorySubtreeOpRootCheck(allowed=False)

    target_masks = evaluate_path_masks(
        subject,
        paths[target.id],
        eval_time_utc=now,
        check_ancestor_traverse=check_traverse,
    )
    return DirectorySubtreeOpRootCheck(
        allowed=True,
        target_inherited=target_masks.target_inherited,
        dest_ancestor_ids=frozenset(node.node_id for node in paths[target_parent.id]),
        eval_time_utc=now,
    )


def _authorize_deleted_subtree_descendants(
    session: OrmSession,
    user: User,
    target_id: str,
    descendant_rows: Sequence[_SubtreeNodeLike],
    root_check: DirectorySubtreeOpRootCheck,
    *,
    evaluate_fn: Callable[
        [
            Subject | None,
            str,
            InheritedDaclState,
            Sequence[SubtreeNode],
            datetime.datetime | None,
        ],
        EvalDecision,
    ],
    op_name: str,
) -> EvalDecision:
    if not root_check.allowed:
        return EvalDecision(
            allowed=False,
            reason=f"{op_name} on target failed.",
            step=f"5_composite_{op_name.lower()}_target",
        )
    non_deleted = [
        row for row in descendant_rows if int(row.status) != EntityStatus.DELETED.value
    ]
    if non_deleted:
        first = non_deleted[0]
        return EvalDecision(
            allowed=False,
            reason=(
                f"{op_name} is not applicable to non-deleted descendant "
                f"'{first.name}' ({first.id})."
            ),
            step="1_lifecycle_and_type",
        )
    if root_check.bypass_dacl or not descendant_rows:
        return EvalDecision(
            allowed=True,
            reason=f"Subtree {op_name.lower()} authorized.",
            step="5_composite_allowed",
        )

    now = root_check.eval_time_utc or datetime.datetime.now(datetime.UTC)
    preloaded_inherit = {row.id: bool(row.inherit) for row in descendant_rows}
    policies = load_node_policies(
        session,
        list(preloaded_inherit.keys()),
        include_deleted=True,
        preloaded_inherit=preloaded_inherit,
        exclude_expired_before=now,
        canonicalize=False,
    )
    subtree_nodes = _build_subtree_nodes(descendant_rows, target_id, policies)
    return evaluate_fn(
        user_to_subject(user),
        target_id,
        root_check.target_inherited,
        subtree_nodes,
        now,
    )


def authorize_purge_descendants(
    session: OrmSession,
    user: User,
    target_id: str,
    descendant_rows: Sequence[_SubtreeNodeLike],
    root_check: DirectorySubtreeOpRootCheck,
) -> EvalDecision:
    """Load only descendant DACLs and verify PURGE + deleted state in O(N * R)."""
    return _authorize_deleted_subtree_descendants(
        session,
        user,
        target_id,
        descendant_rows,
        root_check,
        evaluate_fn=evaluate_purge_subtree,
        op_name="PURGE",
    )


def authorize_restore_descendants(
    session: OrmSession,
    user: User,
    target_id: str,
    descendant_rows: Sequence[_SubtreeNodeLike],
    root_check: DirectorySubtreeOpRootCheck,
) -> EvalDecision:
    """Load only descendant DACLs and verify RESTORE + deleted state in O(N * R)."""
    return _authorize_deleted_subtree_descendants(
        session,
        user,
        target_id,
        descendant_rows,
        root_check,
        evaluate_fn=evaluate_restore_subtree,
        op_name="RESTORE",
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

    if has_bypass_dacl(user):
        return EvalDecision(
            allowed=True,
            reason="Allowed by global BYPASS_DACL capability.",
            step="0_bypass_dacl",
        )

    reparenting = (target.parent_id or ROOT_DIRECTORY_ID) != target_parent.id
    now = eval_time_utc or datetime.datetime.now(datetime.UTC)
    paths = load_ancestor_paths_for_nodes(
        session,
        [target, target_parent],
        exclude_expired_before=now,
        canonicalize=False,
    )
    return evaluate_restore(
        user_to_subject(user),
        paths[target.id],
        paths[target_parent.id],
        reparenting=reparenting,
        eval_time_utc=now,
        check_ancestor_traverse=should_check_ancestor_traverse(session, user),
        collect_traces=False,
    )


def would_self_lockout_on_create(
    session: OrmSession,
    user: User,
    parent: Folder,
    object_type: ObjectType,
    name: str,
    proposed_policy: CompiledPolicy,
    *,
    create_check: CreateAuthzCheck | None = None,
    eval_time_utc: datetime.datetime | None = None,
) -> bool:
    """Return True if saving proposed_policy on a newly created child would revoke the actor's WRITE_DACL."""
    if has_bypass_dacl(user):
        return False

    now = (
        eval_time_utc
        or (create_check.eval_time_utc if create_check is not None else None)
        or datetime.datetime.now(datetime.UTC)
    )
    resolved_path = (
        create_check.parent_path
        if create_check is not None and create_check.parent_path is not None
        else _load_ancestor_path(
            session,
            parent,
            exclude_expired_before=now,
            canonicalize=False,
        )
    )
    check_traverse = (
        create_check.check_ancestor_traverse
        if create_check is not None
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
        collect_traces=False,
    )
    return not post_check.allowed

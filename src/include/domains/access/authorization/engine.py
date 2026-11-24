__all__ = [
    "EffectiveMasksResult",
    "EvalDecision",
    "InheritedDaclState",
    "MatchedRuleTrace",
    "NamespaceNode",
    "ObjectState",
    "PathMasksResult",
    "SaveAuthzResult",
    "Subject",
    "SubtreeNode",
    "authorize_policy_save",
    "eval_dnf",
    "evaluate_access",
    "evaluate_effective_masks",
    "evaluate_path_masks",
    "evaluate_reparent",
    "evaluate_soft_delete",
    "evaluate_soft_delete_subtree",
    "op_applies_to_object",
    "op_applies_to_state",
    "rule_active_at",
    "rule_next_transition_after",
    "scope_matches",
    "step_node_dacl",
]

import datetime
from collections import defaultdict, deque
from collections.abc import Sequence
from dataclasses import dataclass, field
from enum import StrEnum
from uuid import UUID

from cacl_compiler import (
    ATOMIC_OP_BY_FLAG,
    AtomicOp,
    CompiledPolicy,
    CompiledRule,
    ConditionAtom,
    DNFClause,
    Effect,
    ObjectType,
    PredicateKind,
    Scope,
)
from cacl_compiler.permissions import StateApplicability, TargetApplicability


class ObjectState(StrEnum):
    NORMAL = "normal"
    SOFT_DELETED = "soft_deleted"


@dataclass(frozen=True, slots=True)
class Subject:
    """Authenticated security principal (CEP 2 Section 1)."""

    user_id: UUID
    groups: frozenset[str] = frozenset()
    perms: frozenset[str] = frozenset()
    _user_id_str: str = field(init=False, repr=False, compare=False)

    def __post_init__(self) -> None:
        object.__setattr__(self, "_user_id_str", str(self.user_id))


@dataclass(frozen=True, slots=True)
class NamespaceNode:
    node_id: str
    name: str
    object_type: ObjectType
    state: ObjectState
    policy: CompiledPolicy


@dataclass(frozen=True, slots=True)
class SubtreeNode:
    node_id: str
    parent_id: str
    name: str
    object_type: ObjectType
    state: ObjectState
    policy: CompiledPolicy


@dataclass(frozen=True, slots=True)
class InheritedDaclState:
    """Effective inheritable DACL masks accumulated from ancestors."""

    dir_allow: int = 0
    dir_deny: int = 0
    dir_next: datetime.datetime | None = None
    doc_allow: int = 0
    doc_deny: int = 0
    doc_next: datetime.datetime | None = None


_EMPTY_INHERITED_STATE = InheritedDaclState()


@dataclass(frozen=True, slots=True)
class MatchedRuleTrace:
    node_id: str
    node_name: str
    distance: int
    rule_index: int
    effect: Effect
    scope: Scope
    remark: str | None


@dataclass(frozen=True, slots=True)
class EvalDecision:
    allowed: bool
    reason: str
    step: str
    matched_denies: tuple[MatchedRuleTrace, ...] = ()
    matched_allows: tuple[MatchedRuleTrace, ...] = ()
    effective_allow_mask: int = 0
    effective_deny_mask: int = 0
    next_transition_at: datetime.datetime | None = None


@dataclass(frozen=True, slots=True)
class EffectiveMasksResult:
    allowed_traverse: bool
    effective_allow_mask: int
    effective_deny_mask: int
    effective_mask: int
    next_transition_at: datetime.datetime | None = None
    denied_step: str | None = None
    denied_reason: str | None = None


@dataclass(frozen=True, slots=True)
class PathMasksResult:
    target: EffectiveMasksResult
    target_inherited: InheritedDaclState = _EMPTY_INHERITED_STATE
    parent_effective_mask: int = 0
    parent_state: ObjectState | None = None


@dataclass(frozen=True, slots=True)
class SaveAuthzResult:
    authorized: bool
    reason: str
    self_lockout_warning: bool = False


def op_applies_to_object(op: AtomicOp, obj_type: ObjectType) -> bool:
    meta = ATOMIC_OP_BY_FLAG[op]
    if meta.target is TargetApplicability.BOTH:
        return True
    return meta.target.value == obj_type.value


def op_applies_to_state(op: AtomicOp, state: ObjectState) -> bool:
    meta = ATOMIC_OP_BY_FLAG[op]
    if meta.state is StateApplicability.BOTH:
        return True
    return meta.state.value == state.value


def _min_transition(
    a: datetime.datetime | None,
    b: datetime.datetime | None,
) -> datetime.datetime | None:
    if a is None:
        return b
    if b is None:
        return a
    return min(b, a)


def scope_matches(scope: Scope, distance: int, target_type: ObjectType) -> bool:
    """CEP 2 Section 4 Scope Matching Matrix."""
    if scope is Scope.SELF:
        return distance == 0
    if scope is Scope.DIRS:
        return target_type is ObjectType.DIRECTORY
    if scope is Scope.DOCS:
        return target_type is ObjectType.DOCUMENT
    return True


def rule_active_at(rule: CompiledRule, eval_time_utc: datetime.datetime) -> bool:
    """Half-open interval check: valid_from <= t < valid_until."""
    if rule.valid_from is not None and eval_time_utc < rule.valid_from:
        return False
    return not (rule.valid_until is not None and eval_time_utc >= rule.valid_until)


def _rule_next_transition_utc(
    rule: CompiledRule,
    now_utc: datetime.datetime,
) -> datetime.datetime | None:
    vf = rule.valid_from
    vu = rule.valid_until
    if vf is not None and vf > now_utc:
        if vu is not None and vu > now_utc:
            return min(vu, vf)
        return vf
    if vu is not None and vu > now_utc:
        return vu
    return None


def rule_next_transition_after(
    rule: CompiledRule,
    at_utc: datetime.datetime,
) -> datetime.datetime | None:
    """Earliest temporal validity boundary strictly after ``at_utc``."""
    if at_utc.tzinfo is None:
        raise ValueError("at_utc must be timezone-aware")
    return _rule_next_transition_utc(rule, at_utc.astimezone(datetime.UTC))


def _eval_atom(atom: ConditionAtom, subject: Subject) -> bool:
    if atom.kind is PredicateKind.USER:
        matched = atom.value == subject._user_id_str
    elif atom.kind is PredicateKind.GROUP:
        matched = atom.value in subject.groups
    elif atom.kind is PredicateKind.PERM:
        matched = atom.value in subject.perms
    else:
        matched = False
    return (not matched) if atom.negated else matched


def eval_dnf(clauses: tuple[DNFClause, ...], subject: Subject) -> bool:
    for clause in clauses:
        if all(_eval_atom(atom, subject) for atom in clause.atoms):
            return True
    return False


def step_node_dacl(
    subject: Subject,
    policy: CompiledPolicy,
    object_type: ObjectType,
    inherited: InheritedDaclState,
    eval_time_utc: datetime.datetime,
) -> tuple[int, int, datetime.datetime | None, InheritedDaclState]:
    """Propagate inherited DACL state through one node in O(rules) time."""
    base = inherited if policy.inherit else _EMPTY_INHERITED_STATE
    dir_allow = base.dir_allow
    dir_deny = base.dir_deny
    dir_next = base.dir_next
    doc_allow = base.doc_allow
    doc_deny = base.doc_deny
    doc_next = base.doc_next
    self_allow = 0
    self_deny = 0
    self_next: datetime.datetime | None = None

    if policy.rules:
        for rule in policy.rules:
            if not eval_dnf(rule.dnf_clauses, subject):
                continue
            nt = _rule_next_transition_utc(rule, eval_time_utc)
            mask = rule.permission_mask if rule_active_at(rule, eval_time_utc) else 0
            is_deny = rule.effect is Effect.DENY
            scope = rule.scope
            if scope is Scope.SELF:
                self_next = _min_transition(self_next, nt)
                if mask:
                    if is_deny:
                        self_deny |= mask
                    else:
                        self_allow |= mask
            elif scope is Scope.DIRS:
                dir_next = _min_transition(dir_next, nt)
                if mask:
                    if is_deny:
                        dir_deny |= mask
                    else:
                        dir_allow |= mask
            elif scope is Scope.DOCS:
                doc_next = _min_transition(doc_next, nt)
                if mask:
                    if is_deny:
                        doc_deny |= mask
                    else:
                        doc_allow |= mask
            else:
                dir_next = _min_transition(dir_next, nt)
                doc_next = _min_transition(doc_next, nt)
                if mask:
                    if is_deny:
                        dir_deny |= mask
                        doc_deny |= mask
                    else:
                        dir_allow |= mask
                        doc_allow |= mask

    if object_type is ObjectType.DIRECTORY:
        own_allow = dir_allow | self_allow
        own_deny = dir_deny | self_deny
        own_next = _min_transition(dir_next, self_next)
    else:
        own_allow = doc_allow | self_allow
        own_deny = doc_deny | self_deny
        own_next = _min_transition(doc_next, self_next)

    next_inherited = InheritedDaclState(
        dir_allow=dir_allow,
        dir_deny=dir_deny,
        dir_next=dir_next,
        doc_allow=doc_allow,
        doc_deny=doc_deny,
        doc_next=doc_next,
    )
    return own_allow, own_deny, own_next, next_inherited


_TRAVERSE_BIT = int(AtomicOp.TRAVERSE)
_DELETE_BIT = int(AtomicOp.DELETE)


def _collect_op_traces_on_chain(
    subject: Subject,
    chain_root_to_target: list[NamespaceNode],
    op: AtomicOp,
    eval_time_utc: datetime.datetime,
) -> tuple[list[MatchedRuleTrace], list[MatchedRuleTrace]]:
    target = chain_root_to_target[-1]
    op_bit = int(op)
    matched_denies: list[MatchedRuleTrace] = []
    matched_allows: list[MatchedRuleTrace] = []

    for dist, node in enumerate(reversed(chain_root_to_target)):
        if node.policy.rules:
            for idx, rule in enumerate(node.policy.rules):
                if not (rule.permission_mask & op_bit):
                    continue
                if not scope_matches(rule.scope, dist, target.object_type):
                    continue
                if not rule_active_at(rule, eval_time_utc):
                    continue
                if not eval_dnf(rule.dnf_clauses, subject):
                    continue
                trace = MatchedRuleTrace(
                    node.node_id,
                    node.name,
                    dist,
                    idx,
                    rule.effect,
                    rule.scope,
                    rule.remark,
                )
                if rule.effect is Effect.DENY:
                    matched_denies.append(trace)
                else:
                    matched_allows.append(trace)
        if not node.policy.inherit:
            break

    return matched_denies, matched_allows


def evaluate_path_masks(
    subject: Subject | None,
    path_root_to_target: list[NamespaceNode],
    eval_time_utc: datetime.datetime | None = None,
    check_ancestor_traverse: bool = True,
) -> PathMasksResult:
    """Compute target effective masks, inheritable state, and immediate parent masks in O(D * R)."""
    if not path_root_to_target:
        raise ValueError("path_root_to_target must contain at least the target node.")
    if subject is None:
        return PathMasksResult(
            target=EffectiveMasksResult(
                allowed_traverse=False,
                effective_allow_mask=0,
                effective_deny_mask=0,
                effective_mask=0,
                denied_step="0_unauthenticated",
                denied_reason="Unauthenticated request: not a DACL principal.",
            )
        )

    now = (eval_time_utc or datetime.datetime.now(datetime.UTC)).astimezone(
        datetime.UTC
    )
    target = path_root_to_target[-1]
    inherited = _EMPTY_INHERITED_STATE
    next_transition: datetime.datetime | None = None
    parent_idx = len(path_root_to_target) - 2
    parent_effective_mask = 0
    parent_state: ObjectState | None = None

    for idx in range(len(path_root_to_target) - 1):
        ancestor = path_root_to_target[idx]
        if (
            check_ancestor_traverse
            and ancestor.state is not ObjectState.NORMAL
            and target.state is not ObjectState.SOFT_DELETED
        ):
            return PathMasksResult(
                target=EffectiveMasksResult(
                    allowed_traverse=False,
                    effective_allow_mask=0,
                    effective_deny_mask=0,
                    effective_mask=0,
                    next_transition_at=next_transition,
                    denied_step="2_path_traverse",
                    denied_reason=(
                        f"Ancestor '{ancestor.name}' ({ancestor.node_id}) is not in normal state."
                    ),
                )
            )
        own_allow, own_deny, own_next, inherited = step_node_dacl(
            subject, ancestor.policy, ancestor.object_type, inherited, now
        )
        if idx == parent_idx:
            parent_state = ancestor.state
            parent_effective_mask = own_allow & ~own_deny
        if check_ancestor_traverse:
            if ancestor.state is not ObjectState.NORMAL:
                continue
            next_transition = _min_transition(next_transition, own_next)
            if not ((own_allow & _TRAVERSE_BIT) and not (own_deny & _TRAVERSE_BIT)):
                return PathMasksResult(
                    target=EffectiveMasksResult(
                        allowed_traverse=False,
                        effective_allow_mask=0,
                        effective_deny_mask=0,
                        effective_mask=0,
                        next_transition_at=next_transition,
                        denied_step="2_path_traverse",
                        denied_reason=(
                            f"Missing TRAVERSE permission on ancestor '{ancestor.name}' ({ancestor.node_id})."
                        ),
                    )
                )

    a_mask, d_mask, target_next, target_inherited = step_node_dacl(
        subject, target.policy, target.object_type, inherited, now
    )
    next_transition = _min_transition(next_transition, target_next)
    return PathMasksResult(
        target=EffectiveMasksResult(
            allowed_traverse=True,
            effective_allow_mask=a_mask,
            effective_deny_mask=d_mask,
            effective_mask=a_mask & ~d_mask,
            next_transition_at=next_transition,
        ),
        target_inherited=target_inherited,
        parent_effective_mask=parent_effective_mask,
        parent_state=parent_state,
    )


def evaluate_effective_masks(
    subject: Subject | None,
    path_root_to_target: list[NamespaceNode],
    eval_time_utc: datetime.datetime | None = None,
    check_ancestor_traverse: bool = True,
) -> EffectiveMasksResult:
    """Compute effective 21-bit allow/deny masks and cache TTL bound in one O(D * R) pass."""
    return evaluate_path_masks(
        subject,
        path_root_to_target,
        eval_time_utc=eval_time_utc,
        check_ancestor_traverse=check_ancestor_traverse,
    ).target


def evaluate_access(
    subject: Subject | None,
    path_root_to_target: list[NamespaceNode],
    operation: AtomicOp,
    eval_time_utc: datetime.datetime | None = None,
    check_ancestor_traverse: bool = True,
) -> EvalDecision:
    """CEP 2 Section 6 deterministic runtime evaluation pipeline in O(D * R)."""
    if not path_root_to_target:
        raise ValueError("path_root_to_target must contain at least the target node.")

    if subject is None:
        return EvalDecision(
            allowed=False,
            reason="Unauthenticated request: not a DACL principal.",
            step="0_unauthenticated",
        )

    now = (eval_time_utc or datetime.datetime.now(datetime.UTC)).astimezone(
        datetime.UTC
    )
    target = path_root_to_target[-1]

    if not op_applies_to_object(operation, target.object_type):
        return EvalDecision(
            allowed=False,
            reason=f"Operation {operation.name} is not applicable to {target.object_type.value}.",
            step="1_lifecycle_and_type",
        )
    if not op_applies_to_state(operation, target.state):
        return EvalDecision(
            allowed=False,
            reason=f"Operation {operation.name} is not applicable in state {target.state.value}.",
            step="1_lifecycle_and_type",
        )
    if (
        operation is AtomicOp.RESTORE
        and target.object_type is ObjectType.DIRECTORY
        and len(path_root_to_target) > 1
        and path_root_to_target[-2].state is not ObjectState.NORMAL
    ):
        return EvalDecision(
            allowed=False,
            reason="Cannot restore a directory whose parent directory is not in the normal state.",
            step="1_lifecycle_and_type",
        )

    start_idx = 0
    if not check_ancestor_traverse:
        for idx in range(len(path_root_to_target) - 1, -1, -1):
            if not path_root_to_target[idx].policy.inherit:
                start_idx = idx
                break

    inherited = _EMPTY_INHERITED_STATE
    next_transition: datetime.datetime | None = None
    for idx in range(start_idx, len(path_root_to_target) - 1):
        ancestor = path_root_to_target[idx]
        if (
            check_ancestor_traverse
            and ancestor.state is not ObjectState.NORMAL
            and target.state is not ObjectState.SOFT_DELETED
        ):
            return EvalDecision(
                allowed=False,
                reason=f"Ancestor '{ancestor.name}' ({ancestor.node_id}) is not in normal state.",
                step="2_path_traverse",
                next_transition_at=next_transition,
            )
        own_allow, own_deny, own_next, inherited = step_node_dacl(
            subject, ancestor.policy, ancestor.object_type, inherited, now
        )
        if check_ancestor_traverse:
            if ancestor.state is not ObjectState.NORMAL:
                continue
            next_transition = _min_transition(next_transition, own_next)
            if not ((own_allow & _TRAVERSE_BIT) and not (own_deny & _TRAVERSE_BIT)):
                denies, allows = _collect_op_traces_on_chain(
                    subject,
                    path_root_to_target[: idx + 1],
                    AtomicOp.TRAVERSE,
                    now,
                )
                return EvalDecision(
                    allowed=False,
                    reason=f"Missing TRAVERSE permission on ancestor '{ancestor.name}' ({ancestor.node_id}).",
                    step="2_path_traverse",
                    matched_denies=tuple(denies),
                    matched_allows=tuple(allows),
                    effective_allow_mask=own_allow,
                    effective_deny_mask=own_deny,
                    next_transition_at=next_transition,
                )

    a_mask, d_mask, target_next, _ = step_node_dacl(
        subject, target.policy, target.object_type, inherited, now
    )
    next_transition = _min_transition(next_transition, target_next)
    op_bit = int(operation)
    if (d_mask & op_bit) or (a_mask & op_bit):
        denies, allows = _collect_op_traces_on_chain(
            subject, path_root_to_target, operation, now
        )
    else:
        denies, allows = [], []

    if d_mask & op_bit:
        return EvalDecision(
            allowed=False,
            reason=f"Explicitly denied by {len(denies)} matching deny rule(s).",
            step="4_deny_overrides",
            matched_denies=tuple(denies),
            matched_allows=tuple(allows),
            effective_allow_mask=a_mask,
            effective_deny_mask=d_mask,
            next_transition_at=next_transition,
        )
    if a_mask & op_bit:
        return EvalDecision(
            allowed=True,
            reason=f"Allowed by {len(allows)} matching allow rule(s) with no overriding deny.",
            step="4_allow_matched",
            matched_allows=tuple(allows),
            effective_allow_mask=a_mask,
            effective_deny_mask=d_mask,
            next_transition_at=next_transition,
        )
    return EvalDecision(
        allowed=False,
        reason="Default-deny: no matching allow rule granted the requested operation.",
        step="4_default_deny",
        effective_allow_mask=a_mask,
        effective_deny_mask=d_mask,
        next_transition_at=next_transition,
    )


def evaluate_reparent(
    subject: Subject | None,
    source_path: list[NamespaceNode],
    dest_parent_path: list[NamespaceNode],
    eval_time_utc: datetime.datetime | None = None,
    check_ancestor_traverse: bool = True,
) -> EvalDecision:
    """Step 5: composite authorization for reparenting (REPARENT on source + CREATE_* on dest)."""
    now = (eval_time_utc or datetime.datetime.now(datetime.UTC)).astimezone(
        datetime.UTC
    )
    src_decision = evaluate_access(
        subject,
        source_path,
        AtomicOp.REPARENT,
        now,
        check_ancestor_traverse=check_ancestor_traverse,
    )
    if not src_decision.allowed:
        return EvalDecision(
            allowed=False,
            reason=f"Source check (REPARENT) failed: {src_decision.reason}",
            step="5_composite_source",
            matched_denies=src_decision.matched_denies,
            matched_allows=src_decision.matched_allows,
        )

    src_node = source_path[-1]
    dest_op = (
        AtomicOp.CREATE_DOCUMENT
        if src_node.object_type is ObjectType.DOCUMENT
        else AtomicOp.CREATE_DIRECTORY
    )
    dst_decision = evaluate_access(
        subject,
        dest_parent_path,
        dest_op,
        now,
        check_ancestor_traverse=check_ancestor_traverse,
    )
    if not dst_decision.allowed:
        return EvalDecision(
            allowed=False,
            reason=f"Destination check ({dest_op.name}) failed: {dst_decision.reason}",
            step="5_composite_destination",
            matched_denies=dst_decision.matched_denies,
            matched_allows=dst_decision.matched_allows,
        )
    return EvalDecision(
        allowed=True,
        reason=f"Composite reparent authorized (REPARENT on source + {dest_op.name} on destination).",
        step="5_composite_allowed",
    )


def evaluate_soft_delete_subtree(
    subject: Subject | None,
    target_node_id: str,
    target_effective_mask: int,
    target_inherited: InheritedDaclState,
    descendants: Sequence[SubtreeNode],
    eval_time_utc: datetime.datetime | None = None,
    check_ancestor_traverse: bool = True,
) -> EvalDecision:
    """Verify DELETE (and intermediate TRAVERSE) across all descendants in O(N * R) top-down BFS."""
    if not descendants:
        return EvalDecision(
            allowed=True,
            reason="DELETE granted on target (no non-deleted descendants).",
            step="5_composite_allowed",
        )
    if subject is None:
        return EvalDecision(
            allowed=False,
            reason="Unauthenticated request: not a DACL principal.",
            step="0_unauthenticated",
        )

    now = (eval_time_utc or datetime.datetime.now(datetime.UTC)).astimezone(
        datetime.UTC
    )
    if check_ancestor_traverse and not (target_effective_mask & _TRAVERSE_BIT):
        return EvalDecision(
            allowed=False,
            reason=(
                "Missing DIRECTORY_DELETE_CHILD on target and TRAVERSE denied on target "
                f"({target_node_id}) for descendants."
            ),
            step="5_composite_delete_descendant",
        )

    children_by_parent: dict[str, list[SubtreeNode]] = defaultdict(list)
    for node in descendants:
        children_by_parent[node.parent_id].append(node)

    queue: deque[tuple[str, InheritedDaclState]] = deque(
        [(target_node_id, target_inherited)]
    )
    visited = 0
    while queue:
        parent_id, parent_inherited = queue.popleft()
        for child in children_by_parent.get(parent_id, ()):
            visited += 1
            if not op_applies_to_object(AtomicOp.DELETE, child.object_type):
                return EvalDecision(
                    allowed=False,
                    reason=(
                        "Missing DIRECTORY_DELETE_CHILD on target and DELETE is not applicable "
                        f"to descendant '{child.name}' ({child.node_id})."
                    ),
                    step="5_composite_delete_descendant",
                )
            if not op_applies_to_state(AtomicOp.DELETE, child.state):
                return EvalDecision(
                    allowed=False,
                    reason=(
                        "Missing DIRECTORY_DELETE_CHILD on target and DELETE is not applicable "
                        f"in state {child.state.value} on descendant '{child.name}' ({child.node_id})."
                    ),
                    step="5_composite_delete_descendant",
                )

            own_allow, own_deny, _, child_inherited = step_node_dacl(
                subject, child.policy, child.object_type, parent_inherited, now
            )
            eff_mask = own_allow & ~own_deny
            if not (eff_mask & _DELETE_BIT):
                return EvalDecision(
                    allowed=False,
                    reason=(
                        "Missing DIRECTORY_DELETE_CHILD on target and DELETE denied on descendant "
                        f"'{child.name}' ({child.node_id})."
                    ),
                    step="5_composite_delete_descendant",
                    effective_allow_mask=own_allow,
                    effective_deny_mask=own_deny,
                )

            if (
                child.object_type is ObjectType.DIRECTORY
                and child.node_id in children_by_parent
            ):
                if check_ancestor_traverse and (
                    child.state is not ObjectState.NORMAL
                    or not (eff_mask & _TRAVERSE_BIT)
                ):
                    return EvalDecision(
                        allowed=False,
                        reason=(
                            "Missing DIRECTORY_DELETE_CHILD on target and TRAVERSE denied on descendant "
                            f"directory '{child.name}' ({child.node_id})."
                        ),
                        step="5_composite_delete_descendant",
                        effective_allow_mask=own_allow,
                        effective_deny_mask=own_deny,
                    )
                queue.append((child.node_id, child_inherited))

    if visited != len(descendants):
        raise RuntimeError(
            "Subtree descendants could not all be reached from target directory."
        )

    return EvalDecision(
        allowed=True,
        reason="DELETE granted on target and on every affected descendant.",
        step="5_composite_allowed",
    )


def evaluate_soft_delete(
    subject: Subject | None,
    target_path: list[NamespaceNode],
    descendant_paths: Sequence[list[NamespaceNode]] = (),
    eval_time_utc: datetime.datetime | None = None,
    check_ancestor_traverse: bool = True,
) -> EvalDecision:
    """Step 5: soft-deleting an object, including non-empty directories."""
    now = (eval_time_utc or datetime.datetime.now(datetime.UTC)).astimezone(
        datetime.UTC
    )
    own = evaluate_access(
        subject,
        target_path,
        AtomicOp.DELETE,
        now,
        check_ancestor_traverse=check_ancestor_traverse,
    )
    if not own.allowed:
        return EvalDecision(
            allowed=False,
            reason=f"DELETE on target failed: {own.reason}",
            step="5_composite_delete_target",
            matched_denies=own.matched_denies,
            matched_allows=own.matched_allows,
        )
    if not descendant_paths:
        return EvalDecision(
            allowed=True,
            reason="DELETE granted on target (no non-deleted descendants).",
            step="5_composite_allowed",
        )

    delete_child_bit = int(AtomicOp.DIRECTORY_DELETE_CHILD)
    if (
        target_path[-1].object_type is ObjectType.DIRECTORY
        and target_path[-1].state is ObjectState.NORMAL
        and (own.effective_allow_mask & delete_child_bit)
        and not (own.effective_deny_mask & delete_child_bit)
    ):
        return EvalDecision(
            allowed=True,
            reason="DELETE on target plus DIRECTORY_DELETE_CHILD (per-descendant checks bypassed).",
            step="5_composite_allowed",
        )
    for path in descendant_paths:
        child = evaluate_access(
            subject,
            path,
            AtomicOp.DELETE,
            now,
            check_ancestor_traverse=check_ancestor_traverse,
        )
        if not child.allowed:
            return EvalDecision(
                allowed=False,
                reason=(
                    "Missing DIRECTORY_DELETE_CHILD on target and DELETE denied on descendant "
                    f"'{path[-1].name}' ({path[-1].node_id}): {child.reason}"
                ),
                step="5_composite_delete_descendant",
                matched_denies=child.matched_denies,
                matched_allows=child.matched_allows,
            )
    return EvalDecision(
        allowed=True,
        reason="DELETE granted on target and on every affected descendant.",
        step="5_composite_allowed",
    )


def authorize_policy_save(
    actor: Subject | None,
    current_path: list[NamespaceNode],
    proposed_policy: CompiledPolicy,
    eval_time_utc: datetime.datetime | None = None,
    check_ancestor_traverse: bool = True,
) -> SaveAuthzResult:
    """CEP 2 Section 5.2 Save-time authorization (WRITE_DACL + anti-lockout advisory)."""
    now = (eval_time_utc or datetime.datetime.now(datetime.UTC)).astimezone(
        datetime.UTC
    )
    check = evaluate_access(
        actor,
        current_path,
        AtomicOp.WRITE_DACL,
        now,
        check_ancestor_traverse=check_ancestor_traverse,
    )
    if not check.allowed:
        return SaveAuthzResult(
            authorized=False, reason=f"Missing WRITE_DACL: {check.reason}"
        )

    target = current_path[-1]
    simulated_target = NamespaceNode(
        node_id=target.node_id,
        name=target.name,
        object_type=target.object_type,
        state=target.state,
        policy=proposed_policy,
    )
    post_check = evaluate_access(
        actor,
        current_path[:-1] + [simulated_target],
        AtomicOp.WRITE_DACL,
        now,
        check_ancestor_traverse=check_ancestor_traverse,
    )
    return SaveAuthzResult(
        authorized=True,
        reason="Actor holds WRITE_DACL.",
        self_lockout_warning=not post_check.allowed,
    )

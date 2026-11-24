__all__ = [
    "DIRECTORY_VISIBILITY_MASK",
    "DOCUMENT_VISIBILITY_MASK",
    "EffectiveMasksResult",
    "EvalDecision",
    "InheritedDaclState",
    "MatchedRuleTrace",
    "NamespaceNode",
    "ObjectState",
    "PathMasksResult",
    "Subject",
    "SubtreeNode",
    "eval_dnf",
    "evaluate_access",
    "evaluate_effective_masks",
    "evaluate_path_masks",
    "evaluate_reparent",
    "evaluate_soft_delete_subtree",
    "op_applies_to_object",
    "op_applies_to_state",
    "rule_active_at",
    "scope_matches",
    "simulate_policy_save_lockout",
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
class _PathWalkResult:
    allowed_traverse: bool
    allow_mask: int = 0
    deny_mask: int = 0
    next_transition_at: datetime.datetime | None = None
    target_inherited: InheritedDaclState = _EMPTY_INHERITED_STATE
    parent_effective_mask: int = 0
    parent_state: ObjectState | None = None
    denied_reason: str | None = None
    denied_traverse_ancestor_idx: int | None = None


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


def _merge_rule_mask(
    allow: int,
    deny: int,
    next_t: datetime.datetime | None,
    mask: int,
    is_deny: bool,
    nt: datetime.datetime | None,
) -> tuple[int, int, datetime.datetime | None]:
    next_t = _min_transition(next_t, nt)
    if mask:
        if is_deny:
            deny |= mask
        else:
            allow |= mask
    return allow, deny, next_t


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

    for rule in policy.rules:
        if not eval_dnf(rule.dnf_clauses, subject):
            continue
        nt = _rule_next_transition_utc(rule, eval_time_utc)
        mask = rule.permission_mask if rule_active_at(rule, eval_time_utc) else 0
        is_deny = rule.effect is Effect.DENY
        scope = rule.scope
        if scope is Scope.SELF:
            self_allow, self_deny, self_next = _merge_rule_mask(
                self_allow, self_deny, self_next, mask, is_deny, nt
            )
        elif scope is Scope.DIRS:
            dir_allow, dir_deny, dir_next = _merge_rule_mask(
                dir_allow, dir_deny, dir_next, mask, is_deny, nt
            )
        elif scope is Scope.DOCS:
            doc_allow, doc_deny, doc_next = _merge_rule_mask(
                doc_allow, doc_deny, doc_next, mask, is_deny, nt
            )
        else:
            dir_allow, dir_deny, dir_next = _merge_rule_mask(
                dir_allow, dir_deny, dir_next, mask, is_deny, nt
            )
            doc_allow, doc_deny, doc_next = _merge_rule_mask(
                doc_allow, doc_deny, doc_next, mask, is_deny, nt
            )

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


DIRECTORY_VISIBILITY_MASK = int(AtomicOp.LIST_DIRECTORY | AtomicOp.READ_METADATA)
DOCUMENT_VISIBILITY_MASK = int(AtomicOp.READ_CONTENT | AtomicOp.READ_METADATA)
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


def _walk_path_dacl(
    subject: Subject,
    path_root_to_target: list[NamespaceNode],
    eval_time_utc: datetime.datetime,
    *,
    check_ancestor_traverse: bool,
    track_parent: bool = False,
) -> _PathWalkResult:
    target = path_root_to_target[-1]
    parent_idx = len(path_root_to_target) - 2
    start_idx = 0
    if not check_ancestor_traverse:
        scan_from = (
            parent_idx
            if track_parent and len(path_root_to_target) > 1
            else len(path_root_to_target) - 1
        )
        for idx in range(scan_from, -1, -1):
            if not path_root_to_target[idx].policy.inherit:
                start_idx = idx
                break

    inherited = _EMPTY_INHERITED_STATE
    next_transition: datetime.datetime | None = None
    parent_effective_mask = 0
    parent_state: ObjectState | None = None

    for idx in range(start_idx, len(path_root_to_target) - 1):
        ancestor = path_root_to_target[idx]
        if (
            check_ancestor_traverse
            and ancestor.state is not ObjectState.NORMAL
            and target.state is not ObjectState.SOFT_DELETED
        ):
            return _PathWalkResult(
                allowed_traverse=False,
                next_transition_at=next_transition,
                denied_reason=(
                    f"Ancestor '{ancestor.name}' ({ancestor.node_id}) is not in normal state."
                ),
            )
        own_allow, own_deny, own_next, inherited = step_node_dacl(
            subject, ancestor.policy, ancestor.object_type, inherited, eval_time_utc
        )
        if track_parent and idx == parent_idx:
            parent_state = ancestor.state
            parent_effective_mask = own_allow & ~own_deny
        if check_ancestor_traverse:
            if ancestor.state is not ObjectState.NORMAL:
                continue
            next_transition = _min_transition(next_transition, own_next)
            if not ((own_allow & _TRAVERSE_BIT) and not (own_deny & _TRAVERSE_BIT)):
                return _PathWalkResult(
                    allowed_traverse=False,
                    allow_mask=own_allow,
                    deny_mask=own_deny,
                    next_transition_at=next_transition,
                    denied_reason=(
                        f"Missing TRAVERSE permission on ancestor '{ancestor.name}' ({ancestor.node_id})."
                    ),
                    denied_traverse_ancestor_idx=idx,
                )

    a_mask, d_mask, target_next, target_inherited = step_node_dacl(
        subject, target.policy, target.object_type, inherited, eval_time_utc
    )
    next_transition = _min_transition(next_transition, target_next)
    return _PathWalkResult(
        allowed_traverse=True,
        allow_mask=a_mask,
        deny_mask=d_mask,
        next_transition_at=next_transition,
        target_inherited=target_inherited,
        parent_effective_mask=parent_effective_mask,
        parent_state=parent_state,
    )


def _evaluate_path_masks(
    subject: Subject | None,
    path_root_to_target: list[NamespaceNode],
    eval_time_utc: datetime.datetime | None,
    check_ancestor_traverse: bool,
    *,
    track_parent: bool,
) -> PathMasksResult:
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
    walk = _walk_path_dacl(
        subject,
        path_root_to_target,
        now,
        check_ancestor_traverse=check_ancestor_traverse,
        track_parent=track_parent,
    )
    if not walk.allowed_traverse:
        return PathMasksResult(
            target=EffectiveMasksResult(
                allowed_traverse=False,
                effective_allow_mask=0,
                effective_deny_mask=0,
                effective_mask=0,
                next_transition_at=walk.next_transition_at,
                denied_step="2_path_traverse",
                denied_reason=walk.denied_reason,
            )
        )

    return PathMasksResult(
        target=EffectiveMasksResult(
            allowed_traverse=True,
            effective_allow_mask=walk.allow_mask,
            effective_deny_mask=walk.deny_mask,
            effective_mask=walk.allow_mask & ~walk.deny_mask,
            next_transition_at=walk.next_transition_at,
        ),
        target_inherited=walk.target_inherited,
        parent_effective_mask=walk.parent_effective_mask,
        parent_state=walk.parent_state,
    )


def evaluate_path_masks(
    subject: Subject | None,
    path_root_to_target: list[NamespaceNode],
    eval_time_utc: datetime.datetime | None = None,
    check_ancestor_traverse: bool = True,
) -> PathMasksResult:
    """Compute target effective masks, inheritable state, and immediate parent masks in O(D * R)."""
    return _evaluate_path_masks(
        subject,
        path_root_to_target,
        eval_time_utc,
        check_ancestor_traverse,
        track_parent=True,
    )


def evaluate_effective_masks(
    subject: Subject | None,
    path_root_to_target: list[NamespaceNode],
    eval_time_utc: datetime.datetime | None = None,
    check_ancestor_traverse: bool = True,
) -> EffectiveMasksResult:
    """Compute effective 21-bit allow/deny masks and cache TTL bound in one O(D * R) pass."""
    return _evaluate_path_masks(
        subject,
        path_root_to_target,
        eval_time_utc,
        check_ancestor_traverse,
        track_parent=False,
    ).target


def _check_access_preconditions(
    target: NamespaceNode,
    operation: AtomicOp,
    path_root_to_target: list[NamespaceNode],
) -> EvalDecision | None:
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
    return None


def _build_traverse_denial_decision(
    subject: Subject,
    path_root_to_target: list[NamespaceNode],
    walk: _PathWalkResult,
    now: datetime.datetime,
    *,
    collect_traces: bool,
) -> EvalDecision:
    if walk.denied_traverse_ancestor_idx is None:
        return EvalDecision(
            allowed=False,
            reason=walk.denied_reason or "Ancestor is not in normal state.",
            step="2_path_traverse",
            next_transition_at=walk.next_transition_at,
        )

    denies: list[MatchedRuleTrace] = []
    allows: list[MatchedRuleTrace] = []
    if collect_traces:
        denies, allows = _collect_op_traces_on_chain(
            subject,
            path_root_to_target[: walk.denied_traverse_ancestor_idx + 1],
            AtomicOp.TRAVERSE,
            now,
        )
    return EvalDecision(
        allowed=False,
        reason=walk.denied_reason or "Missing TRAVERSE permission on ancestor.",
        step="2_path_traverse",
        matched_denies=tuple(denies),
        matched_allows=tuple(allows),
        effective_allow_mask=walk.allow_mask,
        effective_deny_mask=walk.deny_mask,
        next_transition_at=walk.next_transition_at,
    )


def _build_mask_decision(
    subject: Subject,
    path_root_to_target: list[NamespaceNode],
    operation: AtomicOp,
    walk: _PathWalkResult,
    now: datetime.datetime,
    *,
    collect_traces: bool,
) -> EvalDecision:
    a_mask = walk.allow_mask
    d_mask = walk.deny_mask
    next_transition = walk.next_transition_at
    op_bit = int(operation)
    denies: list[MatchedRuleTrace] = []
    allows: list[MatchedRuleTrace] = []
    if collect_traces and ((d_mask & op_bit) or (a_mask & op_bit)):
        denies, allows = _collect_op_traces_on_chain(
            subject, path_root_to_target, operation, now
        )

    if d_mask & op_bit:
        return EvalDecision(
            allowed=False,
            reason=(
                f"Explicitly denied by {len(denies)} matching deny rule(s)."
                if collect_traces
                else "Explicitly denied by matching deny rule."
            ),
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
            reason=(
                f"Allowed by {len(allows)} matching allow rule(s) with no overriding deny."
                if collect_traces
                else "Allowed by matching allow rule with no overriding deny."
            ),
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


def evaluate_access(
    subject: Subject | None,
    path_root_to_target: list[NamespaceNode],
    operation: AtomicOp,
    eval_time_utc: datetime.datetime | None = None,
    check_ancestor_traverse: bool = True,
    *,
    collect_traces: bool = True,
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
    precondition_denial = _check_access_preconditions(
        path_root_to_target[-1], operation, path_root_to_target
    )
    if precondition_denial is not None:
        return precondition_denial

    walk = _walk_path_dacl(
        subject,
        path_root_to_target,
        now,
        check_ancestor_traverse=check_ancestor_traverse,
        track_parent=False,
    )
    if not walk.allowed_traverse:
        return _build_traverse_denial_decision(
            subject, path_root_to_target, walk, now, collect_traces=collect_traces
        )

    return _build_mask_decision(
        subject,
        path_root_to_target,
        operation,
        walk,
        now,
        collect_traces=collect_traces,
    )


def evaluate_reparent(
    subject: Subject | None,
    source_path: list[NamespaceNode],
    dest_parent_path: list[NamespaceNode],
    eval_time_utc: datetime.datetime | None = None,
    check_ancestor_traverse: bool = True,
    *,
    collect_traces: bool = True,
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
        collect_traces=collect_traces,
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
        collect_traces=collect_traces,
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


def _evaluate_descendant_delete(
    subject: Subject,
    child: SubtreeNode,
    parent_inherited: InheritedDaclState,
    now: datetime.datetime,
    *,
    has_children: bool,
    check_ancestor_traverse: bool,
) -> tuple[EvalDecision | None, InheritedDaclState]:
    if not op_applies_to_object(AtomicOp.DELETE, child.object_type):
        return (
            EvalDecision(
                allowed=False,
                reason=(
                    "Missing DIRECTORY_DELETE_CHILD on target and DELETE is not applicable "
                    f"to descendant '{child.name}' ({child.node_id})."
                ),
                step="5_composite_delete_descendant",
            ),
            _EMPTY_INHERITED_STATE,
        )
    if not op_applies_to_state(AtomicOp.DELETE, child.state):
        return (
            EvalDecision(
                allowed=False,
                reason=(
                    "Missing DIRECTORY_DELETE_CHILD on target and DELETE is not applicable "
                    f"in state {child.state.value} on descendant '{child.name}' ({child.node_id})."
                ),
                step="5_composite_delete_descendant",
            ),
            _EMPTY_INHERITED_STATE,
        )

    own_allow, own_deny, _, child_inherited = step_node_dacl(
        subject, child.policy, child.object_type, parent_inherited, now
    )
    eff_mask = own_allow & ~own_deny
    if not (eff_mask & _DELETE_BIT):
        return (
            EvalDecision(
                allowed=False,
                reason=(
                    "Missing DIRECTORY_DELETE_CHILD on target and DELETE denied on descendant "
                    f"'{child.name}' ({child.node_id})."
                ),
                step="5_composite_delete_descendant",
                effective_allow_mask=own_allow,
                effective_deny_mask=own_deny,
            ),
            child_inherited,
        )

    if (
        has_children
        and check_ancestor_traverse
        and (child.state is not ObjectState.NORMAL or not (eff_mask & _TRAVERSE_BIT))
    ):
        return (
            EvalDecision(
                allowed=False,
                reason=(
                    "Missing DIRECTORY_DELETE_CHILD on target and TRAVERSE denied on descendant "
                    f"directory '{child.name}' ({child.node_id})."
                ),
                step="5_composite_delete_descendant",
                effective_allow_mask=own_allow,
                effective_deny_mask=own_deny,
            ),
            child_inherited,
        )
    return None, child_inherited


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
            has_children = (
                child.object_type is ObjectType.DIRECTORY
                and child.node_id in children_by_parent
            )
            denial, child_inherited = _evaluate_descendant_delete(
                subject,
                child,
                parent_inherited,
                now,
                has_children=has_children,
                check_ancestor_traverse=check_ancestor_traverse,
            )
            if denial is not None:
                return denial
            if has_children:
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


def simulate_policy_save_lockout(
    actor: Subject | None,
    current_path: list[NamespaceNode],
    proposed_policy: CompiledPolicy,
    eval_time_utc: datetime.datetime | None = None,
    check_ancestor_traverse: bool = True,
) -> bool:
    """Return True if replacing current_path[-1]'s policy with proposed_policy revokes WRITE_DACL."""
    if not current_path:
        raise ValueError("current_path must contain at least the target node.")
    now = (eval_time_utc or datetime.datetime.now(datetime.UTC)).astimezone(
        datetime.UTC
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
        [*current_path[:-1], simulated_target],
        AtomicOp.WRITE_DACL,
        now,
        check_ancestor_traverse=check_ancestor_traverse,
        collect_traces=False,
    )
    return not post_check.allowed

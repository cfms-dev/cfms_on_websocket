__all__ = [
    "EffectiveMasksResult",
    "EvalDecision",
    "MatchedRuleTrace",
    "NamespaceNode",
    "ObjectState",
    "SaveAuthzResult",
    "Subject",
    "authorize_policy_save",
    "eval_dnf",
    "evaluate_access",
    "evaluate_effective_masks",
    "evaluate_reparent",
    "evaluate_soft_delete",
    "op_applies_to_object",
    "op_applies_to_state",
    "rule_active_at",
    "rule_next_transition_after",
    "scope_matches",
]

import datetime
from collections.abc import Sequence
from dataclasses import dataclass
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


@dataclass(frozen=True, slots=True)
class NamespaceNode:
    node_id: str
    name: str
    object_type: ObjectType
    state: ObjectState
    policy: CompiledPolicy


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


def rule_next_transition_after(
    rule: CompiledRule,
    at_utc: datetime.datetime,
) -> datetime.datetime | None:
    """Earliest temporal validity boundary strictly after ``at_utc``."""
    if at_utc.tzinfo is None:
        raise ValueError("at_utc must be timezone-aware")
    ref = at_utc.astimezone(datetime.UTC)
    candidates = [
        ts for ts in (rule.valid_from, rule.valid_until) if ts is not None and ts > ref
    ]
    return min(candidates) if candidates else None


def _eval_atom(atom: ConditionAtom, subject: Subject) -> bool:
    if atom.kind is PredicateKind.USER:
        matched = atom.value == str(subject.user_id)
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


def _evaluate_dacl_on_chain(
    subject: Subject,
    chain_root_to_target: list[NamespaceNode],
    op: AtomicOp | None,
    eval_time_utc: datetime.datetime,
) -> tuple[
    bool,
    list[MatchedRuleTrace],
    list[MatchedRuleTrace],
    int,
    int,
    datetime.datetime | None,
]:
    """Steps 3 & 4: Assemble inherited DACLs (respecting `inherit off`) and apply deny-overrides."""
    target = chain_root_to_target[-1]
    effective_nodes: list[tuple[int, NamespaceNode]] = []
    for dist, node in enumerate(reversed(chain_root_to_target)):
        effective_nodes.append((dist, node))
        if not node.policy.inherit:
            break

    matched_denies: list[MatchedRuleTrace] = []
    matched_allows: list[MatchedRuleTrace] = []
    allow_mask = 0
    deny_mask = 0
    next_transition: datetime.datetime | None = None
    op_bit = int(op) if op is not None else 0

    for dist, node in effective_nodes:
        if not node.policy.rules:
            continue
        for idx, rule in enumerate(node.policy.rules):
            if not scope_matches(rule.scope, dist, target.object_type):
                continue
            if not eval_dnf(rule.dnf_clauses, subject):
                continue
            next_transition = _min_transition(
                next_transition, rule_next_transition_after(rule, eval_time_utc)
            )
            if not rule_active_at(rule, eval_time_utc):
                continue

            if rule.effect is Effect.DENY:
                deny_mask |= rule.permission_mask
                if op_bit and (rule.permission_mask & op_bit):
                    matched_denies.append(
                        MatchedRuleTrace(
                            node.node_id,
                            node.name,
                            dist,
                            idx,
                            Effect.DENY,
                            rule.scope,
                            rule.remark,
                        )
                    )
            else:
                allow_mask |= rule.permission_mask
                if op_bit and (rule.permission_mask & op_bit):
                    matched_allows.append(
                        MatchedRuleTrace(
                            node.node_id,
                            node.name,
                            dist,
                            idx,
                            Effect.ALLOW,
                            rule.scope,
                            rule.remark,
                        )
                    )

    if matched_denies:
        return (
            False,
            matched_denies,
            matched_allows,
            allow_mask,
            deny_mask,
            next_transition,
        )
    if matched_allows:
        return (
            True,
            matched_denies,
            matched_allows,
            allow_mask,
            deny_mask,
            next_transition,
        )
    return (
        False,
        matched_denies,
        matched_allows,
        allow_mask,
        deny_mask,
        next_transition,
    )


def evaluate_effective_masks(
    subject: Subject | None,
    path_root_to_target: list[NamespaceNode],
    eval_time_utc: datetime.datetime | None = None,
    check_ancestor_traverse: bool = True,
) -> EffectiveMasksResult:
    """Compute effective 21-bit allow/deny masks and cache TTL bound in one pass."""
    if not path_root_to_target:
        raise ValueError("path_root_to_target must contain at least the target node.")
    if subject is None:
        return EffectiveMasksResult(
            allowed_traverse=False,
            effective_allow_mask=0,
            effective_deny_mask=0,
            effective_mask=0,
            denied_step="0_unauthenticated",
            denied_reason="Unauthenticated request: not a DACL principal.",
        )

    now = (eval_time_utc or datetime.datetime.now(datetime.UTC)).astimezone(
        datetime.UTC
    )
    target = path_root_to_target[-1]
    next_transition: datetime.datetime | None = None

    if check_ancestor_traverse and len(path_root_to_target) > 1:
        for idx in range(len(path_root_to_target) - 1):
            ancestor = path_root_to_target[idx]
            if ancestor.state is not ObjectState.NORMAL:
                if target.state is ObjectState.SOFT_DELETED:
                    continue
                return EffectiveMasksResult(
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
            ok, _, _, _, _, anc_next = _evaluate_dacl_on_chain(
                subject, path_root_to_target[: idx + 1], AtomicOp.TRAVERSE, now
            )
            next_transition = _min_transition(next_transition, anc_next)
            if not ok:
                return EffectiveMasksResult(
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

    _, _, _, a_mask, d_mask, target_next = _evaluate_dacl_on_chain(
        subject, path_root_to_target, None, now
    )
    next_transition = _min_transition(next_transition, target_next)
    return EffectiveMasksResult(
        allowed_traverse=True,
        effective_allow_mask=a_mask,
        effective_deny_mask=d_mask,
        effective_mask=a_mask & ~d_mask,
        next_transition_at=next_transition,
    )


def evaluate_access(
    subject: Subject | None,
    path_root_to_target: list[NamespaceNode],
    operation: AtomicOp,
    eval_time_utc: datetime.datetime | None = None,
    check_ancestor_traverse: bool = True,
) -> EvalDecision:
    """CEP 2 Section 6 deterministic runtime evaluation pipeline."""
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

    next_transition: datetime.datetime | None = None
    if check_ancestor_traverse and len(path_root_to_target) > 1:
        for idx in range(len(path_root_to_target) - 1):
            ancestor = path_root_to_target[idx]
            if ancestor.state is not ObjectState.NORMAL:
                if target.state is ObjectState.SOFT_DELETED:
                    continue
                return EvalDecision(
                    allowed=False,
                    reason=f"Ancestor '{ancestor.name}' ({ancestor.node_id}) is not in normal state.",
                    step="2_path_traverse",
                    next_transition_at=next_transition,
                )
            ok, denies, allows, a_mask, d_mask, anc_next = _evaluate_dacl_on_chain(
                subject, path_root_to_target[: idx + 1], AtomicOp.TRAVERSE, now
            )
            next_transition = _min_transition(next_transition, anc_next)
            if not ok:
                return EvalDecision(
                    allowed=False,
                    reason=f"Missing TRAVERSE permission on ancestor '{ancestor.name}' ({ancestor.node_id}).",
                    step="2_path_traverse",
                    matched_denies=tuple(denies),
                    matched_allows=tuple(allows),
                    effective_allow_mask=a_mask,
                    effective_deny_mask=d_mask,
                    next_transition_at=next_transition,
                )

    _allowed, denies, allows, a_mask, d_mask, target_next = _evaluate_dacl_on_chain(
        subject, path_root_to_target, operation, now
    )
    next_transition = _min_transition(next_transition, target_next)
    if denies:
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
    if allows:
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

    bypass = evaluate_access(
        subject,
        target_path,
        AtomicOp.DIRECTORY_DELETE_CHILD,
        now,
        check_ancestor_traverse=check_ancestor_traverse,
    )
    if bypass.allowed:
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

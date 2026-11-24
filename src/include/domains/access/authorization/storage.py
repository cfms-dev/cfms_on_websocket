__all__ = [
    "DEFAULT_ROOT_DACL_SOURCE",
    "compile_policy_source",
    "delete_node_dacl_rules_for_targets",
    "load_node_policies",
    "persist_node_policy",
    "render_policy_text",
]

import datetime
import uuid
from collections import defaultdict
from collections.abc import Iterable, Mapping, Sequence
from itertools import batched

from cacl_compiler import (
    CompiledPolicy,
    CompiledRule,
    CompilerConfig,
    CompileResult,
    ConditionAtom,
    DecompileOptions,
    Diagnostic,
    DNFClause,
    Effect,
    ObjectType,
    PredicateKind,
    Scope,
    Severity,
    collect_principal_refs,
    compile_ast,
    decompile_policy,
    parse_cacl,
)
from cacl_compiler.ast_nodes import PolicyAST
from sqlalchemy import delete, or_, select
from sqlalchemy.orm import Session as OrmSession

from include.config.constants import (
    DACL_MAX_RULES_PER_NODE,
    QUERY_CHUNK_SIZE,
)
from include.database.models.access import (
    NodeDaclAtom,
    NodeDaclClause,
    NodeDaclRule,
)
from include.database.models.documents import Document, Folder, Node
from include.database.models.identity import User, UserGroup

DEFAULT_ROOT_DACL_SOURCE = (
    "inherit off;\n"
    'allow [PRESET_READ] to any remark "Default read access for authenticated users";\n'
    "allow [PRESET_RW, PRESET_TRASH_RW, PRESET_ACL_RW, READ_REVISION, DELETE_REVISION] "
    'to group("sysop") remark "Default administrator full access";\n'
)


def _validate_ast_principals(
    session: OrmSession,
    ast: PolicyAST,
    *,
    strict_principals: bool,
) -> list[Diagnostic]:
    """Batch-validate AST user UUID and group references against the live database."""
    refs = collect_principal_refs(ast)
    if not refs:
        return []

    user_uuids = {
        uuid.UUID(ref.value) for ref in refs if ref.kind is PredicateKind.USER
    }
    group_names = {ref.value for ref in refs if ref.kind is PredicateKind.GROUP}

    existing_users: set[uuid.UUID] = set()
    for chunk in batched(user_uuids, QUERY_CHUNK_SIZE):
        existing_users.update(
            session.scalars(select(User.id).where(User.id.in_(list(chunk)))).all()
        )

    existing_groups: set[str] = set()
    for chunk in batched(group_names, QUERY_CHUNK_SIZE):
        existing_groups.update(
            session.scalars(
                select(UserGroup.group_name).where(
                    UserGroup.group_name.in_(list(chunk))
                )
            ).all()
        )

    severity = Severity.ERROR if strict_principals else Severity.WARNING
    diags: list[Diagnostic] = []
    for ref in refs:
        if ref.kind is PredicateKind.USER:
            if uuid.UUID(ref.value) not in existing_users:
                diags.append(
                    Diagnostic(
                        code="E301" if strict_principals else "W301",
                        severity=severity,
                        message=f"User UUID '{ref.value}' does not exist in principal directory.",
                        span=ref.span,
                    )
                )
        elif ref.kind is PredicateKind.GROUP and ref.value not in existing_groups:
            diags.append(
                Diagnostic(
                    code="E303" if strict_principals else "W304",
                    severity=severity,
                    message=f"Group '{ref.value}' does not exist in principal directory.",
                    span=ref.span,
                )
            )
    return diags


def _resolve_user_annotations(
    session: OrmSession,
    raw_user_ids: Iterable[str],
) -> dict[str, str]:
    uuids: set[uuid.UUID] = set()
    for raw_uid in raw_user_ids:
        try:
            uuids.add(uuid.UUID(raw_uid))
        except ValueError:
            pass

    annotations: dict[str, str] = {}
    for chunk in batched(uuids, QUERY_CHUNK_SIZE):
        rows = session.execute(
            select(User.id, User.username).where(User.id.in_(list(chunk)))
        ).all()
        for uid, username in rows:
            annotations[str(uid)] = username
    return annotations


def compile_policy_source(
    session: OrmSession,
    source: str,
    *,
    target_type: ObjectType | None = None,
    strict_principals: bool = False,
    now_utc: datetime.datetime | None = None,
) -> CompileResult:
    """Compile CACL policy source and batch-validate referenced principals against the database."""
    ast, parse_diags = parse_cacl(source)
    if ast is None or any(d.severity is Severity.ERROR for d in parse_diags):
        return CompileResult(policy=None, diagnostics=parse_diags)

    config = CompilerConfig(
        target_object_type=target_type,
        now_utc=now_utc or datetime.datetime.now(datetime.UTC),
    )
    compiled = compile_ast(ast, config=config)
    principal_diags = _validate_ast_principals(
        session, ast, strict_principals=strict_principals
    )
    limit_diags: list[Diagnostic] = []
    if (
        compiled.policy is not None
        and len(compiled.policy.rules) > DACL_MAX_RULES_PER_NODE
    ):
        limit_diags.append(
            Diagnostic(
                code="E401",
                severity=Severity.ERROR,
                message=(
                    f"Policy has {len(compiled.policy.rules)} compiled rules, "
                    f"exceeding the maximum of {DACL_MAX_RULES_PER_NODE} rules per node."
                ),
            )
        )
    all_diags = parse_diags + compiled.diagnostics + principal_diags + limit_diags
    has_errors = any(d.severity is Severity.ERROR for d in all_diags)
    return CompileResult(
        policy=None if has_errors else compiled.policy,
        diagnostics=all_diags,
    )


def render_policy_text(
    policy: CompiledPolicy,
    *,
    session: OrmSession | None = None,
    annotate_users: bool = False,
) -> str:
    """Decompile a CompiledPolicy into canonical (or UUID-annotated) CACL text."""
    annotations = (
        _resolve_user_annotations(session, policy.referenced_users())
        if (annotate_users and session is not None)
        else None
    )
    options = DecompileOptions(
        user_annotations=annotations,
        fold_presets=False,
        prefer_to_syntax=True,
        omit_default_scope=True,
        always_emit_inherit=True,
    )
    return decompile_policy(policy, opts=options)


def _build_compiled_rule(
    effect: str,
    permission_mask: int,
    scope: str,
    valid_from: datetime.datetime | None,
    valid_until: datetime.datetime | None,
    remark: str | None,
    clause_ids: Sequence[int],
    atoms_by_clause: Mapping[int, list[ConditionAtom]],
    *,
    canonicalize: bool,
) -> CompiledRule:
    if canonicalize:
        clauses = tuple(
            DNFClause(
                atoms=tuple(
                    sorted(
                        atoms_by_clause.get(cid, ()),
                        key=lambda a: a.sort_key(),
                    )
                )
            )
            for cid in clause_ids
        )
        final_clauses = tuple(
            sorted(clauses, key=lambda c: tuple(a.sort_key() for a in c.atoms))
        )
    else:
        final_clauses = tuple(
            DNFClause(atoms=tuple(atoms_by_clause.get(cid, ()))) for cid in clause_ids
        )
    return CompiledRule(
        effect=Effect(effect),
        permission_mask=int(permission_mask),
        scope=Scope(scope),
        dnf_clauses=final_clauses,
        valid_from=valid_from,
        valid_until=valid_until,
        remark=remark,
    )


def load_node_policies(
    session: OrmSession,
    node_ids: Sequence[str] | Iterable[str],
    *,
    include_deleted: bool = False,
    preloaded_inherit: Mapping[str, bool] | None = None,
    exclude_expired_before: datetime.datetime | None = None,
    active_at_utc: datetime.datetime | None = None,
    canonicalize: bool = True,
) -> dict[str, CompiledPolicy]:
    """Bulk-load CompiledPolicy objects for the requested node IDs using scalar Core queries."""
    unique_ids = list(dict.fromkeys(node_ids))
    if not unique_ids:
        return {}

    exec_opts = {"include_deleted": True} if include_deleted else {}
    inherit_by_node: dict[str, bool] = {}
    if preloaded_inherit is not None:
        for nid in unique_ids:
            if nid in preloaded_inherit:
                inherit_by_node[nid] = bool(preloaded_inherit[nid])

    missing_inherit_ids = [nid for nid in unique_ids if nid not in inherit_by_node]
    for chunk in batched(missing_inherit_ids, QUERY_CHUNK_SIZE):
        node_rows = session.execute(
            select(Node.id, Node.inherit)
            .where(Node.id.in_(list(chunk)))
            .execution_options(**exec_opts)
        ).all()
        for nid, inherit_flag in node_rows:
            inherit_by_node[nid] = bool(inherit_flag)

    active_ref = (
        active_at_utc.astimezone(datetime.UTC) if active_at_utc is not None else None
    )
    expired_ref = (
        exclude_expired_before.astimezone(datetime.UTC)
        if exclude_expired_before is not None
        else None
    )

    existing_ids = [nid for nid in unique_ids if nid in inherit_by_node]
    rules_by_node: dict[str, list[CompiledRule]] = {nid: [] for nid in existing_ids}

    for chunk in batched(existing_ids, QUERY_CHUNK_SIZE):
        chunk_ids = list(chunk)
        rule_stmt = (
            select(
                NodeDaclRule.id,
                NodeDaclRule.node_id,
                NodeDaclRule.effect,
                NodeDaclRule.permission_mask,
                NodeDaclRule.scope,
                NodeDaclRule.valid_from,
                NodeDaclRule.valid_until,
                NodeDaclRule.remark,
            )
            .where(NodeDaclRule.node_id.in_(chunk_ids))
            .order_by(NodeDaclRule.id.asc())
        )
        if active_ref is not None:
            rule_stmt = rule_stmt.where(
                or_(
                    NodeDaclRule.valid_from.is_(None),
                    NodeDaclRule.valid_from <= active_ref,
                ),
                or_(
                    NodeDaclRule.valid_until.is_(None),
                    NodeDaclRule.valid_until > active_ref,
                ),
            )
        elif expired_ref is not None:
            rule_stmt = rule_stmt.where(
                or_(
                    NodeDaclRule.valid_until.is_(None),
                    NodeDaclRule.valid_until > expired_ref,
                ),
            )

        rule_rows = session.execute(rule_stmt).all()
        if not rule_rows:
            continue

        rule_ids = [row[0] for row in rule_rows]
        clauses_by_rule: dict[int, list[int]] = defaultdict(list)
        all_clause_ids: list[int] = []
        for rule_chunk in batched(rule_ids, QUERY_CHUNK_SIZE):
            clause_rows = session.execute(
                select(NodeDaclClause.id, NodeDaclClause.rule_id)
                .where(NodeDaclClause.rule_id.in_(list(rule_chunk)))
                .order_by(NodeDaclClause.id.asc())
            ).all()
            for clause_id, rule_id in clause_rows:
                clauses_by_rule[rule_id].append(clause_id)
                all_clause_ids.append(clause_id)

        atoms_by_clause: dict[int, list[ConditionAtom]] = defaultdict(list)
        if all_clause_ids:
            for clause_chunk in batched(all_clause_ids, QUERY_CHUNK_SIZE):
                atom_rows = session.execute(
                    select(
                        NodeDaclAtom.clause_id,
                        NodeDaclAtom.predicate_kind,
                        NodeDaclAtom.predicate_value,
                        NodeDaclAtom.is_negated,
                    )
                    .where(NodeDaclAtom.clause_id.in_(list(clause_chunk)))
                    .order_by(NodeDaclAtom.id.asc())
                ).all()
                for clause_id, kind, value, is_negated in atom_rows:
                    atoms_by_clause[clause_id].append(
                        ConditionAtom(
                            kind=PredicateKind(kind),
                            value=value,
                            negated=bool(is_negated),
                        )
                    )

        for (
            rule_id,
            node_id,
            effect,
            permission_mask,
            scope,
            valid_from,
            valid_until,
            remark,
        ) in rule_rows:
            rules_by_node[node_id].append(
                _build_compiled_rule(
                    effect,
                    permission_mask,
                    scope,
                    valid_from,
                    valid_until,
                    remark,
                    clauses_by_rule.get(rule_id, ()),
                    atoms_by_clause,
                    canonicalize=canonicalize,
                )
            )

    return {
        nid: CompiledPolicy(
            inherit=inherit_by_node[nid],
            rules=tuple(rules_by_node[nid]),
        )
        for nid in existing_ids
    }


def persist_node_policy(
    session: OrmSession,
    target: Document | Folder,
    policy: CompiledPolicy,
) -> None:
    """Persist a CompiledPolicy onto target within the caller's active transaction."""
    if target.id is None:
        session.flush()
    target_id = target.id
    assert target_id is not None

    node_for_update = (
        session.query(Node)
        .execution_options(include_deleted=True)
        .filter(Node.id == target_id)
        .with_for_update()
        .populate_existing()
        .one_or_none()
    )
    if node_for_update is None:
        raise RuntimeError("Target node no longer exists while persisting DACL policy")

    node_for_update.inherit = policy.inherit
    target.inherit = policy.inherit

    delete_node_dacl_rules_for_targets(session, [target_id])

    for rule in policy.rules:
        orm_rule = NodeDaclRule(
            node_id=target_id,
            effect=rule.effect.value,
            permission_mask=rule.permission_mask,
            scope=rule.scope.value,
            valid_from=rule.valid_from,
            valid_until=rule.valid_until,
            remark=rule.remark,
        )
        for clause in rule.dnf_clauses:
            orm_clause = NodeDaclClause()
            for atom in clause.atoms:
                orm_clause.atoms.append(
                    NodeDaclAtom(
                        predicate_kind=atom.kind.value,
                        predicate_value=atom.value,
                        is_negated=atom.negated,
                    )
                )
            orm_rule.clauses.append(orm_clause)
        session.add(orm_rule)

    session.flush()


def delete_node_dacl_rules_for_targets(
    session: OrmSession,
    node_ids: Iterable[str],
) -> None:
    """Bulk-delete all DACL rules, clauses, and atoms for the given node IDs."""
    unique_ids = list(dict.fromkeys(nid for nid in node_ids if nid))
    if not unique_ids:
        return

    for chunk in batched(unique_ids, QUERY_CHUNK_SIZE):
        chunk_ids = list(chunk)
        rule_ids = list(
            session.scalars(
                select(NodeDaclRule.id).where(NodeDaclRule.node_id.in_(chunk_ids))
            ).all()
        )
        if not rule_ids:
            continue
        for rule_chunk in batched(rule_ids, QUERY_CHUNK_SIZE):
            rule_chunk_ids = list(rule_chunk)
            clause_ids = list(
                session.scalars(
                    select(NodeDaclClause.id).where(
                        NodeDaclClause.rule_id.in_(rule_chunk_ids)
                    )
                ).all()
            )
            for clause_chunk in batched(clause_ids, QUERY_CHUNK_SIZE):
                session.execute(
                    delete(NodeDaclAtom).where(
                        NodeDaclAtom.clause_id.in_(list(clause_chunk))
                    )
                )
            session.execute(
                delete(NodeDaclClause).where(NodeDaclClause.rule_id.in_(rule_chunk_ids))
            )
            session.execute(
                delete(NodeDaclRule).where(NodeDaclRule.id.in_(rule_chunk_ids))
            )

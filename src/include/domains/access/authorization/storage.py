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
from collections.abc import Iterable, Sequence
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
from sqlalchemy import delete, select
from sqlalchemy.orm import Session as OrmSession
from sqlalchemy.orm import selectinload

from include.config.constants import QUERY_CHUNK_SIZE
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
    all_diags = parse_diags + compiled.diagnostics + principal_diags
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


def _orm_rule_to_compiled(rule: NodeDaclRule) -> CompiledRule:
    clauses = tuple(
        DNFClause(
            atoms=tuple(
                sorted(
                    (
                        ConditionAtom(
                            kind=PredicateKind(atom.predicate_kind),
                            value=atom.predicate_value,
                            negated=atom.is_negated,
                        )
                        for atom in clause.atoms
                    ),
                    key=lambda a: a.sort_key(),
                )
            )
        )
        for clause in rule.clauses
    )
    sorted_clauses = tuple(
        sorted(clauses, key=lambda c: tuple(a.sort_key() for a in c.atoms))
    )
    return CompiledRule(
        effect=Effect(rule.effect),
        permission_mask=int(rule.permission_mask),
        scope=Scope(rule.scope),
        dnf_clauses=sorted_clauses,
        valid_from=rule.valid_from,
        valid_until=rule.valid_until,
        remark=rule.remark,
    )


def load_node_policies(
    session: OrmSession,
    node_ids: Sequence[str] | Iterable[str],
    *,
    include_deleted: bool = False,
) -> dict[str, CompiledPolicy]:
    """Bulk-load CompiledPolicy objects for the requested node IDs."""
    unique_ids = list(dict.fromkeys(node_ids))
    if not unique_ids:
        return {}

    exec_opts = {"include_deleted": True} if include_deleted else {}
    inherit_by_node: dict[str, bool] = {}
    rules_by_node: dict[str, list[CompiledRule]] = {nid: [] for nid in unique_ids}

    for chunk in batched(unique_ids, QUERY_CHUNK_SIZE):
        chunk_ids = list(chunk)
        node_rows = session.execute(
            select(Node.id, Node.inherit)
            .where(Node.id.in_(chunk_ids))
            .execution_options(**exec_opts)
        ).all()
        for nid, inherit_flag in node_rows:
            inherit_by_node[nid] = bool(inherit_flag)

        rule_rows = session.scalars(
            select(NodeDaclRule)
            .options(
                selectinload(NodeDaclRule.clauses).selectinload(NodeDaclClause.atoms)
            )
            .where(NodeDaclRule.node_id.in_(chunk_ids))
            .order_by(NodeDaclRule.id.asc())
        ).all()
        for orm_rule in rule_rows:
            rules_by_node[orm_rule.node_id].append(_orm_rule_to_compiled(orm_rule))

    return {
        nid: CompiledPolicy(
            inherit=inherit_by_node[nid],
            rules=tuple(rules_by_node[nid]),
        )
        for nid in unique_ids
        if nid in inherit_by_node
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

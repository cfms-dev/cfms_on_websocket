from __future__ import annotations

from collections import defaultdict
from itertools import batched
from typing import Any, Iterable, Literal

from sqlalchemy import and_, delete
from sqlalchemy.orm import Session as OrmSession
from sqlalchemy.orm import selectinload

from include.config.constants import AVAILABLE_ACCESS_TYPES, QUERY_CHUNK_SIZE
from include.database.models.access import (
    CompiledAccessRule,
    CompiledAccessRuleGroup,
    CompiledAccessRuleMembership,
    CompiledAccessRuleRight,
    CompiledAccessRuleSet,
)
from include.database.models.documents import Node

TargetType = Literal["document", "directory"]
CompiledRuleMap = dict[tuple[TargetType, str], list[CompiledAccessRule]]


def _target_type_and_id(target: Any) -> tuple[TargetType, str] | None:
    from include.database.models.documents import Document, Folder

    if isinstance(target, Document) and target.id:
        return "document", target.id
    if isinstance(target, Folder) and target.id:
        return "directory", target.id
    return None


def _access_rule_types_for(access_type: str) -> tuple[str, ...]:
    if access_type not in AVAILABLE_ACCESS_TYPES:
        raise ValueError(f"Invalid access type: {access_type}")

    match access_type:
        case "read":
            return ("read",)
        case "write":
            return ("read", "write")
        case "move":
            return ("move",)
        case "manage":
            return ("read", "manage")
        case _:
            raise NotImplementedError(f"Unsupported access type: {access_type}")


def active_compiled_rule_conditions(
    *,
    rule,
    rule_set,
    node,
    target_type,
    target_id,
):
    return (
        rule.rule_set_id == rule_set.id,
        rule_set.node_id == node.id,
        node.id == target_id,
        node.type == target_type,
        node.access_rule_set_id == rule_set.id,
    )


def active_compiled_rule_filter(
    *,
    rule,
    rule_set,
    node,
    target_type,
    target_id,
):
    return and_(
        *active_compiled_rule_conditions(
            rule=rule,
            rule_set=rule_set,
            node=node,
            target_type=target_type,
            target_id=target_id,
        )
    )


def _require_list(group_data: dict[str, Any], key: str) -> list[str]:
    value = group_data.get(key, {})
    if not isinstance(value, dict):
        return []
    required = value.get("require", [])
    if not isinstance(required, list):
        return []
    return [str(item) for item in required]


def _compile_match_groups(
    rule_data: dict[str, Any],
) -> Iterable[CompiledAccessRuleGroup]:
    match_groups = rule_data.get("match_groups", [])
    if not isinstance(match_groups, list):
        return []

    compiled_groups: list[CompiledAccessRuleGroup] = []
    for index, group_data in enumerate(match_groups):
        if not isinstance(group_data, dict) or not group_data:
            continue

        rights_group = group_data.get("rights", {})
        if not isinstance(rights_group, dict):
            rights_group = {}
        groups_group = group_data.get("groups", {})
        if not isinstance(groups_group, dict):
            groups_group = {}

        required_rights = _require_list(group_data, "rights")
        required_groups = _require_list(group_data, "groups")
        rights_empty = not required_rights
        groups_empty = not required_groups
        match_mode = group_data.get("match", "all")
        if rights_empty or groups_empty:
            match_mode = "all"

        compiled_group = CompiledAccessRuleGroup(
            group_index=index,
            match_mode=match_mode,
            rights_match_mode=rights_group.get("match", "all"),
            rights_empty=rights_empty,
            groups_match_mode=groups_group.get("match", "all"),
            groups_empty=groups_empty,
        )
        compiled_group.rights.extend(
            CompiledAccessRuleRight(permission=permission)
            for permission in required_rights
        )
        compiled_group.groups.extend(
            CompiledAccessRuleMembership(group_name=group_name)
            for group_name in required_groups
        )
        compiled_groups.append(compiled_group)

    return compiled_groups


def compile_access_rule(
    *,
    target_type: TargetType,
    target_id: str,
    access_type: str,
    rule_data: dict[str, Any],
) -> CompiledAccessRule | None:
    if not rule_data:
        return None

    compiled_rule = CompiledAccessRule(
        access_type=access_type,
        match_mode=rule_data.get("match", "all"),
    )
    compiled_rule.match_groups.extend(_compile_match_groups(rule_data))
    return compiled_rule


def serialize_compiled_access_rule(rule: CompiledAccessRule) -> dict[str, Any]:
    match_groups: list[dict[str, Any]] = []
    for group in rule.match_groups:
        group_data: dict[str, Any] = {}
        if not group.rights_empty:
            group_data["rights"] = {
                "match": group.rights_match_mode,
                "require": [right.permission for right in group.rights],
            }
        if not group.groups_empty:
            group_data["groups"] = {
                "match": group.groups_match_mode,
                "require": [membership.group_name for membership in group.groups],
            }
        if not group.rights_empty and not group.groups_empty:
            group_data["match"] = group.match_mode
        match_groups.append(group_data)

    return {
        "match": rule.match_mode,
        "match_groups": match_groups,
    }


def get_compiled_access_rules(
    session: OrmSession,
    *,
    target_type: TargetType,
    target_id: str,
) -> list[CompiledAccessRule]:
    return (
        session.query(CompiledAccessRule)
        .options(
            selectinload(CompiledAccessRule.rule_set),
            selectinload(CompiledAccessRule.match_groups).selectinload(
                CompiledAccessRuleGroup.rights
            ),
            selectinload(CompiledAccessRule.match_groups).selectinload(
                CompiledAccessRuleGroup.groups
            ),
        )
        .join(CompiledAccessRule.rule_set)
        .join(CompiledAccessRuleSet.node)
        .filter(
            *active_compiled_rule_conditions(
                rule=CompiledAccessRule,
                rule_set=CompiledAccessRuleSet,
                node=Node,
                target_type=target_type,
                target_id=target_id,
            ),
        )
        .order_by(CompiledAccessRule.id.asc())
        .all()
    )


def fetch_compiled_access_rules_for_targets(
    session: OrmSession,
    targets: Iterable[tuple[TargetType, str]],
) -> CompiledRuleMap:
    target_ids_by_type: dict[TargetType, set[str]] = defaultdict(set)
    for target_type, target_id in targets:
        if target_type not in ("document", "directory"):
            raise ValueError(f"Invalid compiled access rule target type: {target_type}")
        if target_id:
            target_ids_by_type[target_type].add(target_id)

    rules_by_target: CompiledRuleMap = {}
    for target_type, target_ids in target_ids_by_type.items():
        for chunk in batched(target_ids, QUERY_CHUNK_SIZE):
            rules = (
                session.query(CompiledAccessRule)
                .options(
                    selectinload(CompiledAccessRule.rule_set),
                    selectinload(CompiledAccessRule.match_groups).selectinload(
                        CompiledAccessRuleGroup.rights
                    ),
                    selectinload(CompiledAccessRule.match_groups).selectinload(
                        CompiledAccessRuleGroup.groups
                    ),
                )
                .join(CompiledAccessRule.rule_set)
                .join(CompiledAccessRuleSet.node)
                .filter(
                    *active_compiled_rule_conditions(
                        rule=CompiledAccessRule,
                        rule_set=CompiledAccessRuleSet,
                        node=Node,
                        target_type=target_type,
                        target_id=Node.id,
                    ),
                    Node.id.in_(list(chunk)),
                )
                .order_by(CompiledAccessRule.id.asc())
                .all()
            )
            for rule in rules:
                rules_by_target.setdefault(
                    (target_type, rule.rule_set.node_id), []
                ).append(rule)

    return rules_by_target


def get_access_rules_json(
    session: OrmSession,
    *,
    target_type: TargetType,
    target_id: str,
) -> dict[str, list[dict[str, Any]]]:
    access_rules: dict[str, list[dict[str, Any]]] = {}
    for rule in get_compiled_access_rules(
        session, target_type=target_type, target_id=target_id
    ):
        access_rules.setdefault(rule.access_type, []).append(
            serialize_compiled_access_rule(rule)
        )
    return access_rules


def get_access_rules_list(
    session: OrmSession,
    *,
    target_type: TargetType,
    target_id: str,
) -> list[dict[str, Any]]:
    return [
        {
            "rule_id": rule.id,
            "rule_data": serialize_compiled_access_rule(rule),
            "access_type": rule.access_type,
        }
        for rule in get_compiled_access_rules(
            session, target_type=target_type, target_id=target_id
        )
    ]


def _compiled_group_matches_user(
    group: CompiledAccessRuleGroup,
    user_permissions: set[str],
    user_groups: set[str],
) -> bool:
    required_rights = {right.permission for right in group.rights}
    if group.rights_empty or not required_rights:
        rights_match = True
    elif group.rights_match_mode == "any":
        rights_match = bool(required_rights & user_permissions)
    else:
        rights_match = required_rights.issubset(user_permissions)

    required_groups = {membership.group_name for membership in group.groups}
    if group.groups_empty or not required_groups:
        groups_match = True
    elif group.groups_match_mode == "any":
        groups_match = bool(required_groups & user_groups)
    else:
        groups_match = required_groups.issubset(user_groups)

    if group.match_mode == "any":
        return rights_match or groups_match
    return rights_match and groups_match


def _compiled_rule_matches_user(rule: CompiledAccessRule, user: Any) -> bool:
    user_permissions = {str(permission) for permission in user.all_permissions}
    user_groups = {str(group_name) for group_name in user.all_groups}

    for group in rule.match_groups:
        matches = _compiled_group_matches_user(group, user_permissions, user_groups)
        if rule.match_mode == "any" and matches:
            return True
        if rule.match_mode == "all" and not matches:
            return False

    return rule.match_mode == "all"


def compiled_rules_allow_from_map(
    rules_by_target: CompiledRuleMap,
    *,
    target_type: TargetType,
    target_id: str,
    user: Any,
    access_type: str,
) -> bool:
    relevant_access_types = _access_rule_types_for(access_type)
    rules = [
        rule
        for rule in rules_by_target.get((target_type, target_id), [])
        if rule.access_type in relevant_access_types
    ]

    if not rules:
        return True

    return all(_compiled_rule_matches_user(rule, user) for rule in rules)


def compiled_rules_allow(
    session: OrmSession,
    *,
    target_type: TargetType,
    target_id: str,
    user: Any,
    access_type: str,
) -> bool:
    relevant_access_types = _access_rule_types_for(access_type)
    rules = (
        session.query(CompiledAccessRule)
        .options(
            selectinload(CompiledAccessRule.match_groups).selectinload(
                CompiledAccessRuleGroup.rights
            ),
            selectinload(CompiledAccessRule.match_groups).selectinload(
                CompiledAccessRuleGroup.groups
            ),
        )
        .join(CompiledAccessRule.rule_set)
        .join(CompiledAccessRuleSet.node)
        .filter(
            *active_compiled_rule_conditions(
                rule=CompiledAccessRule,
                rule_set=CompiledAccessRuleSet,
                node=Node,
                target_type=target_type,
                target_id=target_id,
            ),
            CompiledAccessRule.access_type.in_(relevant_access_types),
        )
        .all()
    )

    if not rules:
        return True

    return all(_compiled_rule_matches_user(rule, user) for rule in rules)


def delete_compiled_access_rules(
    session: OrmSession,
    target_type: TargetType,
    target_id: str,
) -> None:
    delete_compiled_access_rules_for_targets(session, [(target_type, target_id)])


def delete_compiled_access_rules_for_targets(
    session: OrmSession,
    targets: Iterable[tuple[TargetType, str]],
) -> None:
    target_ids_by_type: dict[TargetType, set[str]] = defaultdict(set)
    for target_type, target_id in targets:
        if target_type not in ("document", "directory"):
            raise ValueError(f"Invalid compiled access rule target type: {target_type}")
        if target_id:
            target_ids_by_type[target_type].add(target_id)

    for target_type, target_ids in target_ids_by_type.items():
        for chunk in batched(target_ids, QUERY_CHUNK_SIZE):
            chunk_ids = list(chunk)
            matched_node_ids = {
                row[0]
                for row in session.query(Node.id)
                .filter(Node.id.in_(chunk_ids), Node.type == target_type)
                .all()
            }
            if matched_node_ids != set(chunk_ids):
                invalid_ids = sorted(set(chunk_ids) - matched_node_ids)
                raise ValueError(
                    "Invalid compiled access rule target(s) for "
                    f"{target_type}: {', '.join(invalid_ids)}"
                )

            rule_set_ids = [
                row[0]
                for row in session.query(CompiledAccessRuleSet.id)
                .filter(CompiledAccessRuleSet.node_id.in_(chunk_ids))
                .all()
            ]
            if not rule_set_ids:
                continue

            (
                session.query(Node)
                .filter(Node.id.in_(chunk_ids))
                .update(
                    {Node.access_rule_set_id: None},
                    synchronize_session="fetch",
                )
            )
            session.execute(
                delete(CompiledAccessRuleSet).where(
                    CompiledAccessRuleSet.id.in_(rule_set_ids),
                )
            )


def _compiled_rule_has_invalid_shape(rule: CompiledAccessRule) -> bool:
    if rule.rule_set_id is None:
        return True
    if rule.rule_set is None:
        return True
    if rule.access_type not in AVAILABLE_ACCESS_TYPES:
        return True
    if rule.match_mode not in ("all", "any"):
        return True
    return any(
        group.match_mode not in ("all", "any")
        or group.rights_match_mode not in ("all", "any")
        or group.groups_match_mode not in ("all", "any")
        for group in rule.match_groups
    )


def find_compiled_access_rule_mismatches(
    session: OrmSession,
    *,
    include_orphans: bool = True,
) -> list[tuple[str, str]]:
    """
    Report invalid or orphaned compiled rows.

    Compiled access rules are now the authoritative storage format, so there is
    no legacy source table to compare against or rebuild from.
    """
    mismatches: list[tuple[str, str]] = []

    nodes = (
        session.query(Node)
        .options(
            selectinload(Node.access_rule_set).selectinload(CompiledAccessRuleSet.rules)
        )
        .all()
    )
    valid_node_ids = {node.id for node in nodes}
    node_type_by_id = {node.id: node.type for node in nodes}
    active_rule_set_ids = {
        node.access_rule_set_id for node in nodes if node.access_rule_set_id is not None
    }

    for node in nodes:
        active_rule_set = node.access_rule_set
        if node.access_rule_set_id is not None and active_rule_set is None:
            mismatches.append((node.type, node.id))
            continue
        if active_rule_set is not None and active_rule_set.node_id != node.id:
            mismatches.append((node.type, node.id))
            continue
        if active_rule_set is not None and not active_rule_set.rules:
            mismatches.append((node.type, node.id))

    rule_sets = (
        session.query(CompiledAccessRuleSet)
        .options(
            selectinload(CompiledAccessRuleSet.node),
            selectinload(CompiledAccessRuleSet.rules),
        )
        .all()
    )
    for rule_set in rule_sets:
        if include_orphans and rule_set.node_id not in valid_node_ids:
            mismatches.append(("node", str(rule_set.node_id)))
            continue
        if (
            rule_set.node_id in valid_node_ids
            and rule_set.id not in active_rule_set_ids
        ):
            mismatches.append((node_type_by_id[rule_set.node_id], rule_set.node_id))
            continue
        if not rule_set.rules:
            target_type = node_type_by_id.get(str(rule_set.node_id), "node")
            mismatches.append((target_type, str(rule_set.node_id)))

    rules = (
        session.query(CompiledAccessRule)
        .options(
            selectinload(CompiledAccessRule.rule_set).selectinload(
                CompiledAccessRuleSet.node
            ),
            selectinload(CompiledAccessRule.match_groups),
        )
        .all()
    )
    for rule in rules:
        if rule.rule_set is None:
            mismatches.append(("rule_set", str(rule.rule_set_id)))
            continue
        node_id = rule.rule_set.node_id
        target_type = node_type_by_id.get(str(node_id), "node")
        target_key = (target_type, str(node_id))
        if _compiled_rule_has_invalid_shape(rule):
            mismatches.append(target_key)
            continue
        if include_orphans and node_id not in valid_node_ids:
            mismatches.append(target_key)
            continue

    return sorted(set(mismatches))


def repair_compiled_access_rules(session: OrmSession) -> list[tuple[str, str]]:
    """
    Delete invalid or orphaned compiled rows, then return remaining mismatches.

    This intentionally does not recreate missing rules because compiled rules
    are the only current persisted representation.
    """
    nodes = (
        session.query(Node)
        .options(
            selectinload(Node.access_rule_set).selectinload(CompiledAccessRuleSet.rules)
        )
        .all()
    )
    node_by_id = {node.id: node for node in nodes}
    rule_sets = (
        session.query(CompiledAccessRuleSet)
        .options(selectinload(CompiledAccessRuleSet.rules))
        .all()
    )
    rule_set_by_id = {rule_set.id: rule_set for rule_set in rule_sets}

    for node in nodes:
        active_rule_set = rule_set_by_id.get(str(node.access_rule_set_id))
        if active_rule_set is None:
            node.access_rule_set_id = None
            node.access_rule_set = None
            continue
        if active_rule_set.node_id != node.id or not active_rule_set.rules:
            node.access_rule_set_id = None
            node.access_rule_set = None
    session.flush()

    active_rule_set_ids = {
        node.access_rule_set_id for node in nodes if node.access_rule_set_id is not None
    }
    for rule_set in rule_sets:
        if (
            rule_set.node_id not in node_by_id
            or rule_set.id not in active_rule_set_ids
            or not rule_set.rules
        ):
            session.delete(rule_set)

    for rule in session.query(CompiledAccessRule).options(
        selectinload(CompiledAccessRule.rule_set),
        selectinload(CompiledAccessRule.match_groups),
    ):
        delete_rule = rule.rule_set is None
        if _compiled_rule_has_invalid_shape(rule):
            delete_rule = True
        if delete_rule:
            session.delete(rule)
    session.flush()

    session.expire_all()
    remaining_rule_sets = (
        session.query(CompiledAccessRuleSet)
        .options(selectinload(CompiledAccessRuleSet.rules))
        .all()
    )
    for rule_set in remaining_rule_sets:
        if rule_set.rules:
            continue
        node = session.get(Node, rule_set.node_id)
        if node is not None and node.access_rule_set_id == rule_set.id:
            node.access_rule_set_id = None
            node.access_rule_set = None
        session.delete(rule_set)
    session.flush()
    return find_compiled_access_rule_mismatches(session)

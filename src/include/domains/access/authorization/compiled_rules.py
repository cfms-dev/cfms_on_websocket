from __future__ import annotations

from collections import defaultdict
from itertools import batched
from typing import Any, Iterable, Literal

from sqlalchemy import delete, event
from sqlalchemy.orm import Session as OrmSession
from sqlalchemy.orm import selectinload

from include.config.constants import AVAILABLE_ACCESS_TYPES, QUERY_CHUNK_SIZE
from include.database.models.access import (
    CompiledAccessRule,
    CompiledAccessRuleGroup,
    CompiledAccessRuleMembership,
    CompiledAccessRuleRight,
)

TargetType = Literal["document", "directory"]

_DELETED_TARGET_KEYS = "compiled_access_rule_deleted_target_keys"


def _target_type_and_id(target: Any) -> tuple[TargetType, str] | None:
    from include.database.models.documents import Document, Folder

    if isinstance(target, Document) and target.id:
        return "document", target.id
    if isinstance(target, Folder) and target.id:
        return "directory", target.id
    return None


def _tracked_document_target(target: Any) -> bool:
    from include.database.models.documents import Document, Folder

    return isinstance(target, (Document, Folder))


def _as_match_mode(value: Any) -> str:
    return value if value in ("all", "any") else "all"


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
        match_mode = _as_match_mode(group_data.get("match", "all"))
        if rights_empty or groups_empty:
            match_mode = "all"

        compiled_group = CompiledAccessRuleGroup(
            group_index=index,
            match_mode=match_mode,
            rights_match_mode=_as_match_mode(rights_group.get("match", "all")),
            rights_empty=rights_empty,
            groups_match_mode=_as_match_mode(groups_group.get("match", "all")),
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
        target_type=target_type,
        target_id=target_id,
        access_type=access_type,
        match_mode=_as_match_mode(rule_data.get("match", "all")),
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
            selectinload(CompiledAccessRule.match_groups).selectinload(
                CompiledAccessRuleGroup.rights
            ),
            selectinload(CompiledAccessRule.match_groups).selectinload(
                CompiledAccessRuleGroup.groups
            ),
        )
        .filter(
            CompiledAccessRule.target_type == target_type,
            CompiledAccessRule.target_id == target_id,
        )
        .order_by(CompiledAccessRule.id.asc())
        .all()
    )


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
        .filter(
            CompiledAccessRule.target_type == target_type,
            CompiledAccessRule.target_id == target_id,
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
            session.execute(
                delete(CompiledAccessRule).where(
                    CompiledAccessRule.target_type == target_type,
                    CompiledAccessRule.target_id.in_(list(chunk)),
                )
            )


def _compiled_rule_has_invalid_shape(rule: CompiledAccessRule) -> bool:
    if rule.target_type not in ("document", "directory"):
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
    from include.database.models.documents import Document, Folder

    mismatches: list[tuple[str, str]] = []

    valid_document_ids = {row[0] for row in session.query(Document.id).all()}
    valid_folder_ids = {row[0] for row in session.query(Folder.id).all()}

    rules = (
        session.query(CompiledAccessRule)
        .options(selectinload(CompiledAccessRule.match_groups))
        .all()
    )
    for rule in rules:
        if rule.target_type not in ("document", "directory"):
            mismatches.append((rule.target_type, str(rule.target_id)))
            continue
        target_key = (rule.target_type, str(rule.target_id))
        if _compiled_rule_has_invalid_shape(rule):
            mismatches.append(target_key)
            continue
        if include_orphans:
            if (
                rule.target_type == "document"
                and rule.target_id not in valid_document_ids
            ):
                mismatches.append(("document", str(rule.target_id)))
                continue
            if (
                rule.target_type == "directory"
                and rule.target_id not in valid_folder_ids
            ):
                mismatches.append(("directory", str(rule.target_id)))
                continue

    return sorted(set(mismatches))


def repair_compiled_access_rules(session: OrmSession) -> list[tuple[str, str]]:
    """
    Delete invalid or orphaned compiled rows, then return remaining mismatches.

    This intentionally does not recreate missing rules because compiled rules
    are the only current persisted representation.
    """
    from include.database.models.documents import Document, Folder

    valid_document_ids = {row[0] for row in session.query(Document.id).all()}
    valid_folder_ids = {row[0] for row in session.query(Folder.id).all()}
    for rule in session.query(CompiledAccessRule).all():
        delete_rule = False
        if rule.target_type == "document":
            delete_rule = rule.target_id not in valid_document_ids
        elif rule.target_type == "directory":
            delete_rule = rule.target_id not in valid_folder_ids
        else:
            delete_rule = True
        if _compiled_rule_has_invalid_shape(rule):
            delete_rule = True
        if delete_rule:
            session.delete(rule)
    session.flush()
    return find_compiled_access_rule_mismatches(session)


@event.listens_for(OrmSession, "before_flush")
def _collect_deleted_access_rule_targets(session: OrmSession, *_args) -> None:
    deleted_keys = session.info.setdefault(_DELETED_TARGET_KEYS, set())
    for target in session.deleted:
        if _tracked_document_target(target):
            target_key = _target_type_and_id(target)
            if target_key is not None:
                deleted_keys.add(target_key)


@event.listens_for(OrmSession, "after_flush_postexec")
def _delete_compiled_access_rules_for_deleted_targets(
    session: OrmSession, *_args
) -> None:
    deleted_keys = session.info.pop(_DELETED_TARGET_KEYS, set())
    for target_type, target_id in deleted_keys:
        delete_compiled_access_rules(session, target_type, target_id)

from __future__ import annotations

from typing import Any, Iterable, Literal

from sqlalchemy import delete, event
from sqlalchemy.orm import Session as OrmSession
from sqlalchemy.orm import selectinload

from include.config.constants import AVAILABLE_ACCESS_TYPES
from include.database.models.access import (
    CompiledAccessRule,
    CompiledAccessRuleGroup,
    CompiledAccessRuleMembership,
    CompiledAccessRuleRight,
)
from include.database.session import Session

TargetType = Literal["document", "directory"]

_PENDING_TARGETS_KEY = "compiled_access_rule_pending_targets"
_DELETED_TARGET_KEYS = "compiled_access_rule_deleted_target_keys"


def mark_access_rules_for_compilation(target: Any) -> None:
    setattr(target, "_compile_access_rules_after_flush", True)


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
    source_rule_id: int,
    access_type: str,
    rule_data: dict[str, Any],
) -> CompiledAccessRule | None:
    if not rule_data:
        return None

    compiled_rule = CompiledAccessRule(
        target_type=target_type,
        target_id=target_id,
        source_rule_id=source_rule_id,
        access_type=access_type,
        match_mode=_as_match_mode(rule_data.get("match", "all")),
    )
    compiled_rule.match_groups.extend(_compile_match_groups(rule_data))
    return compiled_rule


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


def rebuild_compiled_access_rules(
    session: OrmSession,
    target: Any,
) -> None:
    target_key = _target_type_and_id(target)
    if target_key is None:
        return
    target_type, target_id = target_key

    session.execute(
        delete(CompiledAccessRule).where(
            CompiledAccessRule.target_type == target_type,
            CompiledAccessRule.target_id == target_id,
        )
    )

    for rule in target.access_rules:
        compiled_rule = compile_access_rule(
            target_type=target_type,
            target_id=target_id,
            source_rule_id=rule.id,
            access_type=rule.access_type,
            rule_data=rule.rule_data,
        )
        if compiled_rule is not None:
            session.add(compiled_rule)


def rebuild_all_compiled_access_rules(session: OrmSession) -> None:
    from include.database.models.documents import Document, Folder

    session.execute(delete(CompiledAccessRuleMembership))
    session.execute(delete(CompiledAccessRuleRight))
    session.execute(delete(CompiledAccessRuleGroup))
    session.execute(delete(CompiledAccessRule))

    for document in (
        session.query(Document).options(selectinload(Document.access_rules)).all()
    ):
        rebuild_compiled_access_rules(session, document)

    for folder in (
        session.query(Folder).options(selectinload(Folder.access_rules)).all()
    ):
        rebuild_compiled_access_rules(session, folder)

    session.flush()


def delete_compiled_access_rules(
    session: OrmSession,
    target_type: TargetType,
    target_id: str,
) -> None:
    session.execute(
        delete(CompiledAccessRule).where(
            CompiledAccessRule.target_type == target_type,
            CompiledAccessRule.target_id == target_id,
        )
    )


def _compiled_rule_signature(rule: CompiledAccessRule) -> tuple:
    groups = []
    for group in sorted(rule.match_groups, key=lambda item: item.group_index):
        groups.append(
            (
                group.group_index,
                group.match_mode,
                group.rights_match_mode,
                group.rights_empty,
                tuple(sorted(right.permission for right in group.rights)),
                group.groups_match_mode,
                group.groups_empty,
                tuple(sorted(membership.group_name for membership in group.groups)),
            )
        )
    return (rule.access_type, rule.match_mode, tuple(groups))


def find_compiled_access_rule_mismatches(
    session: OrmSession,
) -> list[tuple[TargetType, str]]:
    from include.database.models.documents import Document, Folder

    mismatches: list[tuple[TargetType, str]] = []
    targets: list[tuple[TargetType, Any]] = [
        ("document", document)
        for document in session.query(Document)
        .options(selectinload(Document.access_rules))
        .all()
    ]
    targets.extend(
        ("directory", folder)
        for folder in (
            session.query(Folder).options(selectinload(Folder.access_rules)).all()
        )
    )

    for target_type, target in targets:
        expected = []
        for source_rule in target.access_rules:
            compiled_rule = compile_access_rule(
                target_type=target_type,
                target_id=target.id,
                source_rule_id=source_rule.id,
                access_type=source_rule.access_type,
                rule_data=source_rule.rule_data,
            )
            if compiled_rule is not None:
                expected.append(_compiled_rule_signature(compiled_rule))

        actual_rules = (
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
                CompiledAccessRule.target_id == target.id,
            )
            .all()
        )
        actual = [_compiled_rule_signature(rule) for rule in actual_rules]
        if sorted(expected) != sorted(actual):
            mismatches.append((target_type, target.id))

    return mismatches


@event.listens_for(Session, "before_flush")
def _collect_access_rule_targets(session: OrmSession, *_args) -> None:
    pending = session.info.setdefault(_PENDING_TARGETS_KEY, [])
    for target in list(session.new) + list(session.dirty):
        if getattr(target, "_compile_access_rules_after_flush", False):
            pending.append(target)
            setattr(target, "_compile_access_rules_after_flush", False)

    deleted_keys = session.info.setdefault(_DELETED_TARGET_KEYS, set())
    for target in session.deleted:
        if _tracked_document_target(target):
            target_key = _target_type_and_id(target)
            if target_key is not None:
                deleted_keys.add(target_key)


@event.listens_for(Session, "after_flush_postexec")
def _sync_compiled_access_rules(session: OrmSession, *_args) -> None:
    deleted_keys = session.info.pop(_DELETED_TARGET_KEYS, set())
    for target_type, target_id in deleted_keys:
        delete_compiled_access_rules(session, target_type, target_id)

    pending_targets = session.info.pop(_PENDING_TARGETS_KEY, [])
    seen: set[tuple[TargetType, str]] = set()
    for target in pending_targets:
        target_key = _target_type_and_id(target)
        if target_key is None or target_key in deleted_keys or target_key in seen:
            continue
        seen.add(target_key)
        rebuild_compiled_access_rules(session, target)

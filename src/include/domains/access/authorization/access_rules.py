from __future__ import annotations

from typing import TYPE_CHECKING, Any

import jsonschema
from sqlalchemy.orm import Mapped
from sqlalchemy.orm.session import object_session

from include.config.constants import AVAILABLE_ACCESS_TYPES
from include.database.models.identity import User

if TYPE_CHECKING:
    from include.database.models.documents import Document, Folder

__all__ = [
    "AccessRuleBase",
    "apply_access_rules",
    "legacy_rule_data_matches_user",
    "set_access_rules",
    "validate_access_rules",
]


class AccessRuleBase:
    id: Mapped[int]
    access_type: Mapped[str]
    rule_data: Mapped[dict]


ACCESS_RULE_SCHEMA = {
    "type": "array",
    "items": {
        "type": "object",
        "properties": {
            "match": {"type": "string"},
            "match_groups": {
                "type": "array",
                "items": {
                    "type": "object",
                    "properties": {
                        "rights": {
                            "type": "object",
                            "properties": {
                                "match": {"type": "string"},
                                "require": {
                                    "type": "array",
                                    "items": {"type": "string"},
                                },
                            },
                        },
                        "groups": {
                            "type": "object",
                            "properties": {
                                "match": {"type": "string"},
                                "require": {
                                    "type": "array",
                                    "items": {"type": "string"},
                                },
                            },
                        },
                    },
                },
            },
        },
        "required": ["match", "match_groups"],
    },
}


def validate_access_rules(rules: list[dict[str, Any]]) -> None:
    jsonschema.validate(rules, ACCESS_RULE_SCHEMA)


def legacy_rule_data_matches_user(rule_data: dict, user: User) -> bool:
    def match_rights(sub_rights_group):
        if not sub_rights_group:
            return True
        sub_match_mode = sub_rights_group.get("match", "all")
        sub_rights_require = sub_rights_group.get("require", [])
        if not sub_rights_require:
            return True
        if sub_match_mode == "all":
            return set(sub_rights_require).issubset(user.all_permissions)
        if sub_match_mode == "any":
            return any(r in user.all_permissions for r in sub_rights_require)
        raise ValueError('the value of "match" must be "all" or "any"')

    def match_groups(sub_groups_group):
        if not sub_groups_group:
            return True
        sub_match_mode = sub_groups_group.get("match", "all")
        sub_groups_require = sub_groups_group.get("require", [])
        if not sub_groups_require:
            return True
        if sub_match_mode == "all":
            return set(sub_groups_require).issubset(user.all_groups)
        if sub_match_mode == "any":
            return any(g in user.all_groups for g in sub_groups_require)
        raise ValueError('the value of "match" must be "all" or "any"')

    def match_sub_group(sub_group):
        sub_match_mode = sub_group.get("match", "all")
        sub_rights_group = sub_group.get("rights", {})
        sub_groups_group = sub_group.get("groups", {})
        if not sub_rights_group.get("require", []) or not sub_groups_group.get(
            "require", []
        ):
            sub_match_mode = "all"
        if sub_match_mode == "any":
            return match_rights(sub_rights_group) or match_groups(sub_groups_group)
        if sub_match_mode == "all":
            return match_rights(sub_rights_group) and match_groups(sub_groups_group)
        raise ValueError('the value of "match" must be "all" or "any"')

    match_mode = rule_data.get("match", "all")
    for sub_group in rule_data.get("match_groups", []):
        if not sub_group:
            continue
        state = match_sub_group(sub_group)
        if match_mode == "any" and state:
            return True
        if match_mode == "all" and not state:
            return False

    return match_mode == "all"


def set_access_rules(
    target: Document | Folder,
    new_access_rules: dict[str, list[dict]],
    inherit_parent: bool = True,
) -> None:
    """
    Core helper: attach access rules to a Document or Folder without performing
    any user-permission checks.  Only modifies the ORM object — does NOT commit.

    Raises:
        ValueError: if an access type is unrecognised or rule data is null.
        TypeError: if ``target`` is neither a Document nor a Folder.
    """
    from include.database.models.documents import (
        Document,
        DocumentAccessRule,
        Folder,
        FolderAccessRule,
    )
    from include.domains.access.authorization.compiled_rules import (
        mark_access_rules_for_compilation,
    )

    if not new_access_rules:
        for rule in target.access_rules.copy():
            target.access_rules.remove(rule)  # pyright: ignore[reportArgumentType]
        target.inherit = inherit_parent
        mark_access_rules_for_compilation(target)
        return

    for access_type, this_type_rules in new_access_rules.items():
        if access_type not in AVAILABLE_ACCESS_TYPES:
            raise ValueError(f"Invalid access type: {access_type}")

        if this_type_rules is None:
            raise ValueError(
                f"Access rule data for access type {access_type} can't be null"
            )
        validate_access_rules(this_type_rules)

        for rule in target.access_rules.copy():
            if rule.access_type == access_type:
                target.access_rules.remove(rule)  # pyright: ignore[reportArgumentType]

        for each_rule in this_type_rules:
            if each_rule:
                if isinstance(target, Document):
                    this_new_rule = DocumentAccessRule(
                        document_id=target.id,
                        access_type=access_type,
                        rule_data=each_rule,
                    )
                elif isinstance(target, Folder):
                    this_new_rule = FolderAccessRule(
                        folder_id=target.id,
                        access_type=access_type,
                        rule_data=each_rule,
                    )
                else:
                    raise TypeError("Unsupported Object Type")
                target.access_rules.append(
                    this_new_rule  # pyright: ignore[reportArgumentType]
                )

    target.inherit = inherit_parent
    mark_access_rules_for_compilation(target)


def apply_access_rules(
    target: Document | Folder,
    new_access_rules: dict[str, list[dict]],
    user: User,
    inherit_parent: bool = True,
) -> bool:
    """
    Attach access rules and verify the acting user still satisfies each rule.
    Only modifies the ORM object — does NOT commit.

    Returns False if any resulting rule would deny access to ``user``.
    """
    set_access_rules(target, new_access_rules, inherit_parent)
    session = object_session(target)
    if session is not None:
        session.flush()

    for access_type in new_access_rules:
        if not target.check_access_requirements(user, access_type):
            return False

    return True

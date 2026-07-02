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
    "set_access_rules",
    "validate_access_rules",
]


class AccessRuleBase:
    """Base shape for JSON source access rules kept for API compatibility."""

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

__all__ = ["BaseObject"]

import time
from enum import IntEnum
from typing import List, Literal, Optional, cast

from sqlalchemy import VARCHAR, Integer
from sqlalchemy.orm import Mapped, mapped_column
from sqlalchemy.orm.session import object_session

from include.config.constants import AVAILABLE_ACCESS_TYPES
from include.config.settings import global_config
from include.database.session import Base
from include.domains.access.authorization.access_rules import AccessRuleBase
from include.domains.access.authorization.grants import (
    batch_prefetch_granted_ids,
    prefetch_user_blocks,
)
from include.domains.identity.models import User


class EntityStatus(IntEnum):
    OK = 0
    DELETED = 1
    LOCKED = 2


class BaseObject(Base):
    __abstract__ = True

    id: Mapped[str]
    access_rules: Mapped[List]

    # Whether to inherit access rules from parent folders.
    # Useful when enabling recursion check.
    inherit: Mapped[bool]

    status: Mapped[EntityStatus] = mapped_column(
        Integer, nullable=False, default=EntityStatus.OK
    )
    status_operation_id: Mapped[Optional[str]] = mapped_column(
        VARCHAR(255), nullable=True, index=True
    )

    def check_access_requirements(
        self, user: User, access_type: str = "read", _no_recursive_check=False
    ) -> bool:
        """
        Checks if a given user meets the access requirements for a specific access type based on defined access rules.
        Args:
            user (User): The user object whose permissions and groups are to be checked.
            access_type (int, optional): The type of access to check for. Defaults to `"read"`.
            _no_recursive_check (bool, optional): Useful when performing batch queries. Defaults to False.
        Returns:
            bool: True if the user meets all access requirements for the specified access type, False otherwise.
        Raises:
            ValueError: If the "match" value in any rule is not "all" or "any".
        Access rules are evaluated as follows:
            - Each rule may specify required permissions ("rights") and/or groups ("groups").
            - Each requirement can specify a "match" mode: "all" (all required items must be present) or "any" (at least one must be present).
            - Rules are grouped and evaluated according to their match modes and requirements.
            - If no access rules are defined, access is granted by default.
        """

        _TARGET_TYPE_MAPPING = {"folders": "directory", "documents": "document"}

        def match_rights(sub_rights_group):
            if not sub_rights_group:
                return True

            sub_match_mode = sub_rights_group.get("match", "all")
            sub_rights_require = sub_rights_group.get("require", [])

            if not sub_rights_require:
                return True

            if sub_match_mode == "all":
                return set(sub_rights_require).issubset(user.all_permissions)

            elif sub_match_mode == "any":
                for right in sub_rights_require:
                    if right in user.all_permissions:
                        return True
                return False

            else:
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

            elif sub_match_mode == "any":
                for group in sub_groups_require:
                    if group in user.all_groups:
                        return True
                return False
            else:
                raise ValueError('the value of "match" must be "all" or "any"')

        def match_sub_group(sub_group):
            sub_match_mode = sub_group.get("match", "all")
            sub_rights_group = sub_group.get("rights", {})
            sub_groups_group = sub_group.get("groups", {})

            if not (sub_rights_group.get("require", [])) or (
                not sub_groups_group.get("require", [])
            ):
                sub_match_mode = "all"

            if sub_match_mode == "any":
                return match_rights(sub_rights_group) or match_groups(sub_groups_group)
            if sub_match_mode == "all":
                return match_rights(sub_rights_group) and match_groups(sub_groups_group)
            else:
                raise ValueError('the value of "match" must be "all" or "any"')

        def match_primary_sub_group(per_match_group):
            match_mode = per_match_group.get("match", "all")
            for sub_group in per_match_group["match_groups"]:
                if not sub_group:
                    continue

                state = match_sub_group(sub_group)

                if match_mode == "any":
                    if state:
                        return True
                elif match_mode == "all":
                    if not state:
                        return False

            if match_mode == "any":
                return False
            elif match_mode == "all":
                return True

        # Checks whether the user or the user group to which he belongs
        # has special access rights to this object.

        # Get `session` from `User` object
        _session = object_session(user)
        if not _session:
            raise RuntimeError("No active session found for user")

        now = time.time()

        # check user blocks first
        is_globally_blocked, blocked_ids = prefetch_user_blocks(
            _session, user, access_type, now
        )
        if is_globally_blocked or self.id in blocked_ids:
            return False

        # then check special access entries
        self_type = cast(
            Literal["document", "directory"], _TARGET_TYPE_MAPPING[self.__tablename__]
        )
        explicitly_granted_ids = batch_prefetch_granted_ids(
            _session, user, [self.id], self_type, access_type, now
        )

        if self.id in explicitly_granted_ids:
            return True

        if (
            global_config["access"]["enable_access_recursive_check"]
            and self.inherit
            and not _no_recursive_check
        ):
            # FIXME: Use lazy import when Python 3.15 is out
            from include.domains.documents.models import Document, Folder

            # check all parent folders' access rules
            parent = None
            if isinstance(self, Document):
                parent = self.folder
            elif isinstance(self, Folder):
                parent = self.parent

            visited_folder_ids = set()
            while parent is not None:
                if parent.id in visited_folder_ids:
                    # Cycle detected; break to prevent an infinite loop
                    raise RuntimeError("Cycle detected in folder hierarchy")
                visited_folder_ids.add(parent.id)

                if not parent.check_access_requirements(user, access_type=access_type):
                    return False

                if not parent.inherit:
                    break  # if the parent folder does not inherit, stop checking further up

                parent = parent.parent

        if not self.access_rules:
            return True

        for each_rule in self.access_rules:
            if not each_rule:
                continue

            each_rule: AccessRuleBase

            # access_type 一览：
            # read - 读
            # write - 写（删除=清空数据，重命名=写文件元数据，因此都算写）
            # move - 移动
            # manage - 管理

            if access_type not in AVAILABLE_ACCESS_TYPES:
                raise ValueError(
                    f"Invalid access type for {self.__tablename__}: {access_type}"
                )

            match access_type:
                case "read":  # 如果要检查的是读权限
                    if each_rule.access_type != "read":
                        continue
                case "write":  # 如果要检查写权限
                    if each_rule.access_type not in ["read", "write"]:
                        continue
                case "move":
                    # 取消了对读权限的要求
                    if each_rule.access_type != "move":
                        continue
                case "manage":  # 如果要检查管理权限
                    if each_rule.access_type not in ["read", "manage"]:
                        continue
                case _:
                    raise NotImplementedError("Unsupported access type")

            if not each_rule.rule_data:
                continue

            if not match_primary_sub_group(each_rule.rule_data):
                return False

        return True

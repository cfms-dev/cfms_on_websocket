import time
from dataclasses import dataclass
from enum import IntEnum

from sqlalchemy.orm import Session
from sqlalchemy.orm.session import object_session

from include.config.constants import AVAILABLE_ACCESS_TYPES
from include.config.settings import global_config
from include.database.models.access import ObjectAccessEntry
from include.database.models.documents import Document, Folder
from include.database.models.identity import User
from include.domains.access.authorization.compiled_rules import (
    CompiledRuleMap,
    TargetType,
    compiled_rules_allow,
    compiled_rules_allow_from_map,
    fetch_compiled_access_rules_for_targets,
)
from include.domains.access.authorization.grants import prefetch_user_blocks
from include.domains.access.authorization.searchable_tree import (
    load_document_access_context,
    load_user_folder_access_context,
)


class SingleNodeCheckResult(IntEnum):
    ALLOWED_OAE = 2
    ALLOWED = 1
    DENIED = 0


def check_access_requirements(
    session: Session,
    target: Document | Folder,
    user: User,
    access_type: str = "read",
    *,
    recursive: bool | None = None,
) -> bool:
    if recursive is None:
        recursive = global_config["access"]["enable_access_recursive_check"]

    now = time.time()
    if isinstance(target, Document):
        folders, oae_by_target = load_document_access_context(
            session, [target], now=now
        )
        target_type: TargetType = "document"
    else:
        ancestors, oae_by_target = load_user_folder_access_context(
            session,
            [target],
            user,
            access_type,
            now=now,
        )
        folders = [target, *ancestors]
        target_type = "directory"

    folder_map = {folder.id: folder for folder in folders}
    compiled_rules_by_target = fetch_compiled_access_rules_for_targets(
        session,
        [
            (target_type, target.id),
            *(("directory", folder.id) for folder in folders),
        ],
        access_type=access_type,
    )
    is_globally_blocked, blocked_ids = prefetch_user_blocks(
        session, user, access_type, now
    )
    return check_access_for_object(
        target,
        user,
        access_type,
        all_folders=folders,
        oae_by_target=oae_by_target,
        recursive=recursive,
        compiled_rules_by_target=compiled_rules_by_target,
        folder_map=folder_map,
        is_globally_blocked=is_globally_blocked,
        blocked_ids=blocked_ids,
    )


@dataclass(slots=True)
class FolderAccessEvaluationContext:
    user: User
    access_type: str
    folders: list[Folder]
    oae_by_target: dict
    compiled_rules_by_target: CompiledRuleMap
    folder_map: dict[str, Folder]
    is_globally_blocked: bool
    blocked_ids: set[str]

    def allows(self, folder: Folder) -> bool:
        return check_access_for_object(
            folder,
            self.user,
            self.access_type,
            all_folders=self.folders,
            oae_by_target=self.oae_by_target,
            compiled_rules_by_target=self.compiled_rules_by_target,
            folder_map=self.folder_map,
            is_globally_blocked=self.is_globally_blocked,
            blocked_ids=self.blocked_ids,
        )


def load_folder_access_evaluation_context(
    session: Session,
    folders: list[Folder],
    user: User,
    access_type: str,
    *,
    preload_all_rule_types: bool = False,
) -> FolderAccessEvaluationContext:
    now = time.time()
    ancestors, oae_by_target = load_user_folder_access_context(
        session,
        folders,
        user,
        access_type,
        now,
    )
    all_folders = [*folders, *ancestors]
    folder_map = {folder.id: folder for folder in all_folders}
    compiled_rules_by_target = fetch_compiled_access_rules_for_targets(
        session,
        (("directory", folder.id) for folder in all_folders),
        access_type=None if preload_all_rule_types else access_type,
    )
    is_globally_blocked, blocked_ids = prefetch_user_blocks(
        session, user, access_type, now
    )
    return FolderAccessEvaluationContext(
        user=user,
        access_type=access_type,
        folders=all_folders,
        oae_by_target=oae_by_target,
        compiled_rules_by_target=compiled_rules_by_target,
        folder_map=folder_map,
        is_globally_blocked=is_globally_blocked,
        blocked_ids=blocked_ids,
    )


def check_access_for_object(
    obj: Document | Folder,
    user: User,
    access_type: str,
    all_folders: list[Folder],
    oae_by_target: dict,
    recursive: bool = True,
    compiled_rules_by_target: CompiledRuleMap | None = None,
    folder_map: dict[str, Folder] | None = None,
    is_globally_blocked: bool = False,
    blocked_ids: set[str] | None = None,
) -> bool:

    if access_type not in AVAILABLE_ACCESS_TYPES:
        raise ValueError(f"Invalid access type: {access_type}")

    session = object_session(user)
    if session is None:
        raise RuntimeError("No active session found for user")

    if folder_map is None:
        folder_map = {f.id: f for f in all_folders}
    if blocked_ids is None:
        blocked_ids = set()
    if is_globally_blocked:
        return False

    def _check_single_node(node: Document | Folder) -> SingleNodeCheckResult:
        """
        Check if the current user has the specified access type to a single node (document or folder).
        This function performs a three-step access control check:
        1. **Object Access Entry (OAE) Check**: Evaluates special authorization rules with highest priority.
           - First checks if the user has a direct OAE matching the target node, access type, and entity type.
           - Then checks if any of the user's groups have a matching OAE.
           - Returns True immediately if a matching OAE is found.
        2. **Default Allow Rule**: If no access rules are defined on the node, access is granted by default.
        3. **Access Rules Validation**: Iterates through all access rules defined on the node.
           - Filters rules based on the requested access_type (read, write, move, manage).
           - Checks if the user matches the compiled rule requirements.
           - Returns False if any rule fails the matching check.
        Args:
            node: A Document or Folder object to check access permissions for.
        Returns:
            bool: True if the user has the specified access type to the node, False otherwise.
        Raises:
            NotImplementedError: If an unsupported access_type is encountered.
        Note:
            This function relies on external context: `user`, `access_type`, `oae_by_target`,
            and the helper function `_match_primary_sub_group`.
        """

        _TARGET_TYPE_MAPPING: dict[str, TargetType] = {
            "folders": "directory",
            "documents": "document",
        }
        target_type = _TARGET_TYPE_MAPPING[node.__tablename__]

        if node.id in blocked_ids:
            return SingleNodeCheckResult.DENIED

        # check OAE first (highest priority)
        entries: list[ObjectAccessEntry] = oae_by_target.get(node.id, [])

        # check user's direct OAE
        for entry in entries:
            if (
                entry.entity_type == "user"
                and entry.entity_identifier == user.username
                and entry.target_type == target_type
                and entry.access_type == access_type
            ):
                return SingleNodeCheckResult.ALLOWED_OAE

        # check user's group OAE
        user_groups = user.all_groups  # set[str]
        for entry in entries:
            if (
                entry.entity_type == "group"
                and entry.entity_identifier in user_groups
                and entry.target_type == target_type
                and entry.access_type == access_type
            ):
                return SingleNodeCheckResult.ALLOWED_OAE

        if compiled_rules_by_target is None:
            allowed_by_rules = compiled_rules_allow(
                session,
                target_type=target_type,
                target_id=node.id,
                user=user,
                access_type=access_type,
            )
        else:
            allowed_by_rules = compiled_rules_allow_from_map(
                compiled_rules_by_target,
                target_type=target_type,
                target_id=node.id,
                user=user,
                access_type=access_type,
            )

        if allowed_by_rules:
            return SingleNodeCheckResult.ALLOWED
        return SingleNodeCheckResult.DENIED

    # check the object itself first
    match _check_single_node(obj):
        case SingleNodeCheckResult.ALLOWED_OAE:
            return True  # OAE grants access immediately, no need to check further
        case SingleNodeCheckResult.ALLOWED:
            pass  # continue to check parent folders if necessary
        case SingleNodeCheckResult.DENIED:
            return False  # explicit denial, no need to check further
        case _:
            raise RuntimeError("Unexpected SingleNodeCheckResult value")

    # if not recursive or the object does not inherit permissions, stop here
    if not recursive or not obj.inherit:
        return True

    if isinstance(obj, Document):
        current_folder_id = obj.folder_id
    else:  # Folder
        current_folder_id = obj.parent_id

    visited_ids = set()  # prevent potential cycles in folder hierarchy

    while current_folder_id is not None:
        if current_folder_id in visited_ids:
            raise RuntimeError("Cycle detected in folder hierarchy")
        visited_ids.add(current_folder_id)

        current_folder = folder_map.get(current_folder_id)
        if current_folder is None:
            # This should not happen if the folder hierarchy is consistent,
            # but we handle it gracefully just in case
            break

        # check access for the current folder node
        if not _check_single_node(current_folder):
            return False

        # If the current folder does not inherit permissions, stop checking
        # further up the hierarchy
        if not current_folder.inherit:
            break

        current_folder_id = current_folder.parent_id

    return True

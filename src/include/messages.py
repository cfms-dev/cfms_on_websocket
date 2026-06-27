__all__ = ["Messages"]

import gettext
from enum import StrEnum

t = gettext.translation("cfms_server", "include/locale", fallback=True)
_ = t.gettext


class Messages(StrEnum):
    SUCCESS = _("Success")

    SUBJECT_DIRECTORY_NOT_FOUND = _("Subject directory not found")

    DIRECTORY_NOT_FOUND = _("Directory not found")
    DOCUMENT_NOT_FOUND = _("Document not found")
    FOLDER_NOT_FOUND = _("Folder not found")
    DELETED_DIRECTORY_NOT_FOUND = _("Deleted directory not found")
    DELETED_DOCUMENT_NOT_FOUND = _("Deleted document not found")
    TASK_NOT_FOUND = _("Task not found")
    TARGET_DIRECTORY_NOT_FOUND = _("Target directory not found")
    TARGET_DOCUMENT_NOT_FOUND = _("Target document not found")
    KEY_NOT_FOUND = _("Key not found")
    ENTITY_NOT_FOUND = _("Entity not found")
    TARGET_NOT_FOUND = _("Target not found")
    ACCESS_ENTRY_NOT_FOUND = _("Access entry not found")
    GROUP_ALREADY_EXISTS = _("Group already exists")
    USERNAME_ALREADY_EXISTS = _("Username already exists")
    UNSUPPORTED_BLOCK_TYPES = _("Unsupported block type(s)")
    SPECIFIED_ENTRY_NOT_FOUND = _("Specified entry not found")
    SPECIFIED_BLOCK_ENDED = _("The specified block has ended")
    USER_DOES_NOT_EXIST = _("User does not exist")
    ACCOUNT_NOT_ACTIVE = _("Account is not active")
    USER_LACKS_DEBUGGING_PERMISSION = _("User lacks debugging permission.")
    NOT_AFTER_MUST_BE_LATER_THAN_NOT_BEFORE = _(
        "`not_after` must be later than `not_before`"
    )
    DOCUMENT_DOES_NOT_EXIST = _("Document does not exist")

    DIRECTORY_ID_REQUIRED = _("Directory ID is required")
    DOCUMENT_ID_REQUIRED = _("Document ID is required")
    DOCUMENT_TITLE_REQUIRED = _("Document title is required")

    MISSING_USERNAME = _("Username is missing")
    MISSING_USERNAME_OR_TOKEN = _("Username or token is missing")
    INVALID_USER_OR_TOKEN = _("Invalid user or token")
    AUTHENTICATION_REQUIRED = _("Authentication is required")

    ACCESS_DENIED = _("Access denied")
    ACCESS_DENIED_MOVE_DOCUMENT = _("Access denied to move document")
    ACCESS_DENIED_MOVE_DIRECTORY = _("Access denied to move directory")
    ACCESS_DENIED_WRITE_DIRECTORY = _("Access denied to write directory")
    ACCESS_DENIED_SET_ACCESS_RULES = _("Access denied to set access rules")
    ACCESS_DENIED_MANAGE_ACCESS = _(
        "You do not have permission to manage object access"
    )
    PERMISSION_DENIED = _("Permission denied")
    PERMISSION_DENIED_CREATE_GROUP = _("You do not have permission to create groups")

    CANNOT_PURGE_ROOT_DIRECTORY = _("Cannot purge the root directory")
    CANNOT_RESTORE_ROOT_DIRECTORY = _("Cannot restore root directory")
    CANNOT_MOVE_TO_SAME_FOLDER = _("Cannot move to the same folder")
    TARGET_DIRECTORY_NOT_ACTIVE = _("Target directory is not active")

    CANNOT_MOVE_DIRECTORY_INTO_SUBDIRECTORY = _(
        "Cannot move a directory into its own subdirectory"
    )

    NAME_DUPLICATE = _("Name duplicate")
    DOCUMENT_NAME_DUPLICATE = _(
        "A document with the same name already exists in the target directory"
    )
    DIRECTORY_NAME_DUPLICATE = _(
        "A folder with the same name already exists in the target directory"
    )
    DOCUMENT_OR_DIRECTORY_NAME_DUPLICATE = _(
        "A document or folder with the same name already exists in this directory"
    )
    DENIED_FOR_DOC_NAME_DUPLICATE = _(
        "A document with the same name exists, and the file does not have sufficient"
        " permissions to be silently overwritten"
    )

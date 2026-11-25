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
    TARGET_NOT_FOUND = _("Target not found")
    GROUP_ALREADY_EXISTS = _("Group already exists")
    USERNAME_ALREADY_EXISTS = _("Username already exists")
    USER_DOES_NOT_EXIST = _("User does not exist")
    ACCOUNT_NOT_ACTIVE = _("Account is not active")
    USER_LACKS_DEBUGGING_PERMISSION = _("User lacks debugging permission.")
    DOCUMENT_DOES_NOT_EXIST = _("Document does not exist")

    DOCUMENT_TITLE_REQUIRED = _("Document title is required")

    MISSING_USERNAME = _("Username is missing")
    MISSING_USERNAME_OR_TOKEN = _("Username or token is missing")
    INVALID_USER_OR_TOKEN = _("Invalid user or token")
    AUTHENTICATION_REQUIRED = _("Authentication is required")

    ACCESS_DENIED = _("Access denied")
    ACCESS_DENIED_REPARENT_DOCUMENT = _("Access denied to reparent document")
    ACCESS_DENIED_REPARENT_DIRECTORY = _("Access denied to reparent directory")
    ACCESS_DENIED_WRITE_DIRECTORY = _("Access denied to write directory")
    ACCESS_DENIED_READ_DACL = _("Access denied to read DACL")
    ACCESS_DENIED_WRITE_DACL = _("Access denied to write DACL")
    DACL_SELF_LOCKOUT = _(
        "Saving this DACL would revoke your own WRITE_DACL access; pass allow_self_lockout=true to confirm"
    )
    PERMISSION_DENIED = _("Permission denied")
    PERMISSION_DENIED_CREATE_GROUP = _("You do not have permission to create groups")

    CANNOT_PURGE_ROOT_DIRECTORY = _("Cannot purge the root directory")
    CANNOT_RESTORE_ROOT_DIRECTORY = _("Cannot restore root directory")
    CANNOT_REPARENT_TO_SAME_FOLDER = _("Cannot reparent to the same folder")
    TARGET_DIRECTORY_NOT_ACTIVE = _("Target directory is not active")

    CANNOT_REPARENT_DIRECTORY_INTO_SUBDIRECTORY = _(
        "Cannot reparent a directory into its own subdirectory"
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

from collections.abc import Iterator
from contextlib import contextmanager

from sqlalchemy import and_, select
from sqlalchemy.exc import IntegrityError
from sqlalchemy.orm import Session

from include.config.constants import ROOT_DIRECTORY_ID
from include.database.models.documents import Document, EntityStatus, Folder, Node
from include.database.models.identity import User
from include.messages import Messages as smsg

NODE_NAME_UNIQUE_CONSTRAINT = "uq_nodes_active_parent_name"


class NodeNameConflictError(RuntimeError):
    def __init__(self, parent_id: str, name: str) -> None:
        super().__init__(f"Node name {name!r} is already used under {parent_id!r}")
        self.parent_id = parent_id
        self.name = name


def is_node_name_conflict(exc: IntegrityError) -> bool:
    original = exc.orig
    message = str(original)
    lower_message = message.lower()
    if NODE_NAME_UNIQUE_CONSTRAINT in lower_message:
        return True

    sqlstate = getattr(original, "sqlstate", None) or getattr(original, "pgcode", None)
    diagnostic = getattr(original, "diag", None)
    if (
        sqlstate == "23505"
        and getattr(diagnostic, "constraint_name", None) == NODE_NAME_UNIQUE_CONSTRAINT
    ):
        return True

    error_args = getattr(original, "args", ())
    if error_args and error_args[0] == 1062:
        return NODE_NAME_UNIQUE_CONSTRAINT in lower_message

    sqlite_error_name = getattr(original, "sqlite_errorname", "")
    return sqlite_error_name in {"SQLITE_CONSTRAINT", "SQLITE_CONSTRAINT_UNIQUE"} and (
        "nodes.parent_id, nodes.active_name" in lower_message
        or "nodes.active_name, nodes.parent_id" in lower_message
        or "nodes.active_parent_id, nodes.name" in lower_message
        or "nodes.name, nodes.active_parent_id" in lower_message
    )


@contextmanager
def node_name_mutation(session: Session, parent_id: str, name: str) -> Iterator[None]:
    try:
        yield
    except IntegrityError as exc:
        if not is_node_name_conflict(exc):
            raise
        session.rollback()
        raise NodeNameConflictError(parent_id, name) from exc


def get_target_folder_and_check_write(
    session: Session, user: User, target_folder_id: str | None, super_permission: str
) -> tuple[Folder | None, int, str]:
    """
    Looks up the target folder and checks write access.
    Returns (folder_object, error_code, error_message).
    If valid, error_code is 0.
    """
    if not target_folder_id:
        target_folder_id = ROOT_DIRECTORY_ID

    target_folder = session.get(Folder, target_folder_id)
    if not target_folder:
        return None, 404, smsg.TARGET_DIRECTORY_NOT_FOUND

    if not target_folder.check_access_requirements(user, "write"):
        if (
            target_folder_id == ROOT_DIRECTORY_ID
            and super_permission in user.all_permissions
        ):
            return target_folder, 0, ""
        return None, 403, smsg.ACCESS_DENIED_WRITE_DIRECTORY

    return target_folder, 0, ""


def describe_node_name_conflict(
    session: Session, user: User, parent_id: str, name: str
) -> tuple[dict, str]:
    winner = (
        session.query(Node)
        .execution_options(include_deleted=True)
        .filter(
            Node.parent_id == parent_id,
            Node.name == name,
            Node.status != EntityStatus.DELETED,
        )
        .one_or_none()
    )
    if winner is None:
        raise RuntimeError(
            f"Node name conflict winner disappeared under {parent_id!r}: {name!r}"
        )

    return _describe_node_name_conflict_winner(winner, user)


def describe_subtree_restore_name_conflict(
    session: Session,
    user: User,
    status_operation_id: str | None,
    parent_id: str,
    name: str,
) -> tuple[dict, str]:
    if status_operation_id:
        restoring = Node.__table__.alias("restoring_nodes")
        winner = Node.__table__.alias("winning_nodes")
        winner_id = session.execute(
            select(winner.c.id)
            .select_from(
                winner.join(
                    restoring,
                    and_(
                        winner.c.parent_id == restoring.c.parent_id,
                        winner.c.name == restoring.c.name,
                    ),
                )
            )
            .where(
                restoring.c.status_operation_id == status_operation_id,
                restoring.c.status == EntityStatus.DELETED,
                winner.c.status != EntityStatus.DELETED,
                winner.c.id != restoring.c.id,
            )
            .limit(1)
        ).scalar_one_or_none()
        if winner_id is not None:
            winning_node = session.get(
                Node,
                winner_id,
                execution_options={"include_deleted": True},
            )
            if winning_node is not None:
                return _describe_node_name_conflict_winner(winning_node, user)

    return describe_node_name_conflict(session, user, parent_id, name)


def _describe_node_name_conflict_winner(winner: Node, user: User) -> tuple[dict, str]:

    readable = winner.check_access_requirements(user, "read")
    visible_id = winner.id if readable else None
    if isinstance(winner, Document):
        payload = {"type": "document", "id": visible_id}
        message = smsg.DOCUMENT_NAME_DUPLICATE
    elif isinstance(winner, Folder):
        payload = {"type": "directory", "id": visible_id}
        if readable:
            payload["entity"] = winner
        message = smsg.DIRECTORY_NAME_DUPLICATE
    else:
        raise TypeError(f"Unsupported conflicting node type: {winner.type!r}")

    if visible_id is not None:
        payload["duplicate_id"] = visible_id
    return payload, message

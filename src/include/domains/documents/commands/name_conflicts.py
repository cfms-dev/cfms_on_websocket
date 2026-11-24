from contextlib import contextmanager
lazy from collections.abc import Iterator

from sqlalchemy import and_, select
from sqlalchemy.exc import IntegrityError
lazy from sqlalchemy.orm import Session

from include.database.errors import is_unique_constraint_violation
from include.database.models.documents import Document, EntityStatus, Folder, Node
from include.domains.access.authorization.engine import (
    DIRECTORY_VISIBILITY_MASK,
    DOCUMENT_VISIBILITY_MASK,
)
from include.domains.access.authorization.evaluation import (
    evaluate_node_effective_masks,
)
from include.messages import Messages as smsg
lazy from include.database.models.identity import User

NODE_NAME_UNIQUE_CONSTRAINT = "uq_nodes_active_parent_name"


class NodeNameConflictError(RuntimeError):
    def __init__(self, parent_id: str, name: str) -> None:
        super().__init__(f"Node name {name!r} is already used under {parent_id!r}")
        self.parent_id = parent_id
        self.name = name


def is_node_name_conflict(exc: IntegrityError) -> bool:
    return is_unique_constraint_violation(
        exc,
        constraint_name=NODE_NAME_UNIQUE_CONSTRAINT,
        sqlite_column_sets=(
            ("nodes.parent_id", "nodes.active_name"),
            ("nodes.active_parent_id", "nodes.name"),
        ),
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

    return _describe_node_name_conflict_winner(session, winner, user)


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
                return _describe_node_name_conflict_winner(session, winning_node, user)

    return describe_node_name_conflict(session, user, parent_id, name)


def _describe_node_name_conflict_winner(
    session: Session, winner: Node, user: User
) -> tuple[dict, str]:
    if not isinstance(winner, Document | Folder):
        raise TypeError(f"Unsupported conflicting node type: {winner.type!r}")

    masks = evaluate_node_effective_masks(session, user, winner)
    required_mask = (
        DIRECTORY_VISIBILITY_MASK
        if isinstance(winner, Folder)
        else DOCUMENT_VISIBILITY_MASK
    )
    readable = masks.allowed_traverse and bool(masks.effective_mask & required_mask)
    visible_id = winner.id if readable else None
    if isinstance(winner, Document):
        payload = {"type": "document", "id": visible_id}
        message = smsg.DOCUMENT_NAME_DUPLICATE
    else:
        payload = {"type": "directory", "id": visible_id}
        if readable:
            payload["entity"] = winner
        message = smsg.DIRECTORY_NAME_DUPLICATE

    if visible_id is not None:
        payload["duplicate_id"] = visible_id
    return payload, message

from include.database.models.operations import AuditEntry
from include.database.session import Session


def log_audit(
    action: str,
    result: int,
    username: str | None = None,
    target: str | None = None,
    data: dict | None = None,
    remote_address: str | None = None,
) -> None:
    """Create an audit log entry."""
    if result == 400:
        return

    with Session() as session:
        new_entry = AuditEntry(
            action=action,
            username=username,
            target=target,
            result=result,
            data=data,
            remote_address=remote_address,
        )
        session.add(new_entry)
        session.commit()

from typing import Optional

from include.database.models.operations import AuditEntry
from include.database.session import Session


def log_audit(
    action: str,
    result: int,
    username: Optional[str] = None,
    target: Optional[str] = None,
    data: Optional[dict] = None,
    remote_address: Optional[str] = None,
) -> None:
    """创建审计日志。"""
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

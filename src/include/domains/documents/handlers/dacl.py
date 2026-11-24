__all__ = [
    "DaclSource",
    "handle_get_node_dacl",
    "handle_set_node_dacl",
    "prepare_initial_node_dacl",
]

from collections.abc import Callable
from typing import Annotated, Any

from cacl_compiler import CompiledPolicy, ObjectType
from pydantic import StringConstraints
lazy from sqlalchemy.orm import Session as OrmSession

from include.config.constants import DACL_SOURCE_MAX_LENGTH
from include.database.models.documents import Document, Folder
from include.database.models.identity import User
from include.domains.access.authorization.evaluation import (
    CreateAuthzCheck,
    authorize_dacl_read,
    authorize_write_dacl_and_load_path,
    simulate_dacl_save_lockout,
    would_self_lockout_on_create,
)
from include.domains.access.authorization.storage import (
    compile_policy_source,
    persist_node_policy,
    render_policy_text,
)
from include.messages import Messages as smsg
from include.transport.request_handler import Result
lazy from include.transport.connection import ConnectionHandler

DaclSource = Annotated[str, StringConstraints(max_length=DACL_SOURCE_MAX_LENGTH)]


def handle_get_node_dacl(
    session: OrmSession,
    handler: ConnectionHandler,
    *,
    model_cls: type[Folder | Document],
    target_id: str,
    annotate_users: bool,
    not_found_message: str,
    success_message: str,
) -> Result:
    assert handler.user_id is not None
    user = User.get_existing(session, handler.user_id)
    target = session.get(model_cls, target_id)

    if target is None:
        handler.conclude_request(404, {}, not_found_message)
        return Result(code=404, target=target_id, user_id=handler.user_id)

    allowed, policy = authorize_dacl_read(session, user, target)
    if not allowed or policy is None:
        handler.conclude_request(403, {}, smsg.ACCESS_DENIED_READ_DACL)
        return Result(code=403, target=target_id, user_id=handler.user_id)

    response_data: dict[str, Any] = {
        "dacl": render_policy_text(policy),
        "inherit": policy.inherit,
        "fingerprint": policy.fingerprint(),
    }
    if annotate_users:
        response_data["annotated_dacl"] = render_policy_text(
            policy, session=session, annotate_users=True
        )

    handler.conclude_request(200, response_data, success_message)
    return Result(code=0, target=target_id, user_id=handler.user_id)


def handle_set_node_dacl[NodeT: (Folder, Document)](
    session: OrmSession,
    handler: ConnectionHandler,
    *,
    model_cls: type[NodeT],
    target_type: ObjectType,
    target_id: str,
    dacl_source: str,
    allow_self_lockout: bool,
    not_found_message: str,
    success_message: str,
    on_before_commit: Callable[[NodeT, User], None] | None = None,
) -> Result:
    assert handler.user_id is not None
    user = User.get_existing(session, handler.user_id)
    target = session.get(model_cls, target_id)

    if target is None:
        handler.conclude_request(404, {}, not_found_message)
        return Result(code=404, target=target_id, user_id=handler.user_id)

    write_check = authorize_write_dacl_and_load_path(session, user, target)
    if not write_check.authorized:
        handler.conclude_request(403, {}, smsg.ACCESS_DENIED_WRITE_DACL)
        return Result(code=403, target=target_id, user_id=handler.user_id)

    compiled = compile_policy_source(
        session,
        dacl_source,
        target_type=target_type,
        strict_principals=False,
    )
    serialized_diags = [d.to_dict() for d in compiled.diagnostics]
    if not compiled.ok or compiled.policy is None:
        handler.conclude_request(
            400,
            {"diagnostics": serialized_diags},
            "Invalid CACL policy",
        )
        return Result(code=400, target=target_id, user_id=handler.user_id)

    self_lockout_warning = simulate_dacl_save_lockout(
        user,
        write_check.current_path,
        compiled.policy,
        check_ancestor_traverse=write_check.check_ancestor_traverse,
        eval_time_utc=write_check.eval_time_utc,
    )
    if self_lockout_warning and not allow_self_lockout:
        handler.conclude_request(
            409,
            {
                "self_lockout_warning": True,
                "diagnostics": serialized_diags,
            },
            smsg.DACL_SELF_LOCKOUT,
        )
        return Result(code=409, target=target_id, user_id=handler.user_id)

    persist_node_policy(session, target, compiled.policy)
    if on_before_commit is not None:
        on_before_commit(target, user)
    session.commit()

    handler.conclude_request(
        200,
        {
            "dacl": render_policy_text(compiled.policy),
            "inherit": compiled.policy.inherit,
            "fingerprint": compiled.policy.fingerprint(),
            "diagnostics": serialized_diags,
            "self_lockout_warning": self_lockout_warning,
        },
        success_message,
    )
    return Result(code=0, target=target_id, user_id=handler.user_id)


def prepare_initial_node_dacl(
    session: OrmSession,
    user: User,
    parent: Folder,
    *,
    object_type: ObjectType,
    name: str,
    dacl_source: str | None,
    create_check: CreateAuthzCheck,
    allow_self_lockout: bool,
) -> tuple[CompiledPolicy | None, tuple[int, dict[str, Any], str] | None]:
    if dacl_source is None:
        return None, None

    if not create_check.can_write_dacl:
        return None, (403, {}, smsg.ACCESS_DENIED_WRITE_DACL)

    compiled = compile_policy_source(
        session,
        dacl_source,
        target_type=object_type,
        strict_principals=False,
    )
    serialized_diags = [d.to_dict() for d in compiled.diagnostics]
    if not compiled.ok or compiled.policy is None:
        return None, (
            400,
            {"diagnostics": serialized_diags},
            "Invalid CACL policy",
        )

    if not allow_self_lockout and would_self_lockout_on_create(
        session,
        user,
        parent,
        object_type,
        name,
        compiled.policy,
        create_check=create_check,
    ):
        return None, (
            409,
            {
                "self_lockout_warning": True,
                "diagnostics": serialized_diags,
            },
            smsg.DACL_SELF_LOCKOUT,
        )

    return compiled.policy, None

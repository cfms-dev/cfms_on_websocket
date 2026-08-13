import ast
from pathlib import Path
from shutil import copyfile

PROJECT_ROOT = Path(__file__).resolve().parents[2]

EXPECTED_CORE_ACTION_COSTS = {
    "login": 5,
    "refresh_token": 2,
    "setup_2fa": 20,
    "cancel_2fa_setup": 1,
    "validate_2fa": 2,
    "disable_2fa": 5,
    "get_2fa_status": 1,
    "list_banned_subnets": 2,
    "create_banned_subnet": 5,
    "update_banned_subnet": 5,
    "delete_banned_subnet": 5,
    "list_auth_lockouts": 3,
    "unlock_auth_lockouts": 10,
    "get_document": 3,
    "create_document": 5,
    "upload_document": 5,
    "delete_document": 5,
    "restore_document": 3,
    "purge_document": 10,
    "rename_document": 3,
    "move_document": 3,
    "get_document_info": 3,
    "get_document_access_rules": 2,
    "set_document_rules": 5,
    "set_document_tags": 3,
    "list_revisions": 2,
    "get_revision": 3,
    "set_current_revision": 3,
    "delete_revision": 5,
    "download_file": 5,
    "upload_file": 5,
    "list_directory": 3,
    "get_directory_info": 3,
    "get_directory_access_rules": 2,
    "set_directory_rules": 5,
    "create_directory": 3,
    "delete_directory": 10,
    "restore_directory": 10,
    "purge_directory": 20,
    "rename_directory": 3,
    "move_directory": 3,
    "list_deleted_items": 3,
    "search": 3,
    "manage_user_status": 3,
    "block_user": 3,
    "unblock_user": 2,
    "list_user_blocks": 3,
    "list_users": 3,
    "create_user": 5,
    "delete_user": 5,
    "rename_user": 5,
    "get_user_info": 2,
    "get_user_avatar": 3,
    "set_user_avatar": 3,
    "change_user_groups": 3,
    "change_user_permissions": 3,
    "set_passwd": 10,
    "list_groups": 3,
    "create_group": 3,
    "delete_group": 5,
    "rename_group": 5,
    "get_group_info": 3,
    "change_group_permissions": 3,
    "grant_access": 3,
    "revoke_access": 2,
    "view_access_entries": 3,
    "lockdown": 10,
    "view_audit_logs": 3,
    "upload_user_key": 2,
    "get_user_key": 1,
    "delete_user_key": 2,
    "set_user_preference_dek": 2,
    "list_user_keys": 2,
}

EXPECTED_EXTRA_HANDLER_COSTS = {
    "RequestDiagnosticsHandler": 3,
    "RequestServerInfoHandler": 1,
    "RequestShutdownHandler": 1,
    "RequestOIDCStartHandler": 3,
    "RequestOIDCCallbackHandler": 10,
    "RequestThrowExceptionHandler": 3,
}


def _prepare_config(monkeypatch, tmp_path):
    copyfile(PROJECT_ROOT / "src" / "config.toml.sample", tmp_path / "config.toml")
    monkeypatch.chdir(tmp_path)


def _declared_handler_costs(path: Path) -> dict[str, int]:
    module = ast.parse(path.read_text(encoding="utf-8"))
    costs = {}
    for node in module.body:
        if not isinstance(node, ast.ClassDef) or not any(
            isinstance(base, ast.Name) and base.id == "RequestHandler"
            for base in node.bases
        ):
            continue
        assignments = [
            statement.value.value
            for statement in node.body
            if isinstance(statement, ast.Assign)
            and any(
                isinstance(target, ast.Name) and target.id == "rate_limit_cost"
                for target in statement.targets
            )
            and isinstance(statement.value, ast.Constant)
            and isinstance(statement.value.value, int)
        ]
        assert len(assignments) == 1, node.name
        costs[node.name] = assignments[0]
    return costs


def test_core_action_costs_match_business_contract(monkeypatch, tmp_path):
    _prepare_config(monkeypatch, tmp_path)

    from include.transport.request_handler import validate_request_handler_models
    from include.transport.router import available_functions

    validate_request_handler_models(available_functions)
    actual = {
        action: handler_type.rate_limit_cost
        for action, handler_type in available_functions.items()
    }

    assert actual == EXPECTED_CORE_ACTION_COSTS


def test_extra_handler_costs_match_business_contract():
    source_files = (
        PROJECT_ROOT / "src/include/extensions/builtin/_extension.py",
        PROJECT_ROOT / "src/include/extensions/oidc_sso/_extension.py",
        PROJECT_ROOT / "src/include/domains/security/handlers/debugging.py",
    )
    actual = {}
    for source_file in source_files:
        actual.update(_declared_handler_costs(source_file))

    assert actual == EXPECTED_EXTRA_HANDLER_COSTS


def test_all_known_costs_fit_default_request_buckets():
    from include.config.validation import RequestRateControlPolicy

    policy = RequestRateControlPolicy()
    capacity = min(policy.account_capacity, policy.ip_capacity)
    all_costs = (
        *EXPECTED_CORE_ACTION_COSTS.values(),
        *EXPECTED_EXTRA_HANDLER_COSTS.values(),
    )

    assert len(all_costs) == 79
    assert set(all_costs) == {1, 2, 3, 5, 10, 20}
    assert all(0 < cost <= capacity for cost in all_costs)
